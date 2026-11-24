# frozen_string_literal: true

module Ai
  module ActiveContext
    module Queries
      class Code
        include Ai::ActiveContext::Concerns::Loggable
        include Ai::ActiveContext::Concerns::CodeEligibility
        include Ai::ActiveContext::Concerns::RateLimiting

        # Default candidate-pool size and result count for `#filter`. These values were
        # validated against the 160-example MCP tool evaluation -- smaller pools cause
        # agent-driven callers to under-perform and fall back to keyword search.
        KNN_COUNT = 64
        SEARCH_RESULTS_LIMIT = 20
        COLLECTION_CLASS = ::Ai::ActiveContext::Collections::Code

        LAST_QUERIED_UPDATE_INTERVAL = 1.hour

        MESSAGE_INITIAL_INDEXING_STARTED = 'initial indexing has been started, try again in a few minutes'
        MESSAGE_INITIAL_INDEXING_ONGOING = 'initial indexing is still ongoing, try again in a few minutes'
        MESSAGE_ADHOC_INDEXING_TRIGGER_FAILED = 'initial indexing was attempted but could not be started'
        MESSAGE_INDEXING_RATE_LIMITED = 'too many indexing requests for this namespace, please try again later'
        MESSAGE_INDEXING_FAILED = 'indexing failed'
        MESSAGE_NOT_ELIGIBLE = 'the project is not eligible for indexing, please use another tool or context source'

        NotAvailable = Class.new(StandardError)
        ProjectNotFound = Class.new(StandardError)

        def self.available?
          COLLECTION_CLASS.indexing? &&
            search_embedding_model.present? &&
            COLLECTION_CLASS.collection_record.present?
        end

        def self.search_embedding_model
          COLLECTION_CLASS.search_embedding_model
        end

        def initialize(search_term:, user:)
          @search_term = search_term
          @user = user
        end

        def filter(
          project_or_id:,
          path: nil,
          knn_count: KNN_COUNT,
          limit: SEARCH_RESULTS_LIMIT,
          exclude_fields: [],
          extract_source_segments: false,
          build_file_url: false
        )
          check_availability

          project = project_object!(project_or_id)

          ac_repository = find_active_context_repository(project.id)
          return handle_no_ready_active_context_repository(project, ac_repository) unless ac_repository&.ready?

          # Update the last queried timestamp so that we can potentially prune inactive data later
          update_last_queried_timestamp(ac_repository)

          query = if path.nil?
                    repository_query(project.id, knn_count, limit)
                  else
                    directory_query(project.id, path, knn_count, limit)
                  end

          search_hits = COLLECTION_CLASS.search(query: query, user: user)

          prepared_hits = prepare_hits(
            search_hits,
            project,
            exclude_fields: exclude_fields,
            extract_source_segments: extract_source_segments,
            build_file_url: build_file_url
          )
          Result.success(prepared_hits)
        end

        private

        attr_reader :user, :search_term

        def project_object!(project_or_id)
          project = case project_or_id
                    when Project
                      project_or_id
                    when Integer, String
                      Project.find_by_id(project_or_id)
                    else
                      raise(
                        ProjectNotFound,
                        "Project parameter must be a Project object or ID, got #{project_or_id.class}."
                      )
                    end

          if project.nil? || !Ability.allowed?(user, :read_code, project)
            raise(
              ProjectNotFound,
              "Could not find project: #{project_or_id.inspect}."
            )
          end

          project
        end

        def handle_no_ready_active_context_repository(project, ac_repository)
          error_detail = nil

          if ac_repository.nil? || ac_repository.deleted?
            if project_eligible_for_indexing?(project)
              ad_hoc_indexing = try_trigger_ad_hoc_indexing(project)
              error_detail = case ad_hoc_indexing
                             when :rate_limited
                               [MESSAGE_ADHOC_INDEXING_TRIGGER_FAILED, MESSAGE_INDEXING_RATE_LIMITED].join(', ')
                             when false, nil
                               MESSAGE_ADHOC_INDEXING_TRIGGER_FAILED
                             else
                               MESSAGE_INITIAL_INDEXING_STARTED
                             end
            else
              error_detail = MESSAGE_NOT_ELIGIBLE
            end
          elsif ac_repository.failed?
            error_detail = MESSAGE_INDEXING_FAILED
          else
            error_detail = MESSAGE_INITIAL_INDEXING_ONGOING
          end

          Result.no_embeddings_error(error_detail: error_detail)
        end

        def try_trigger_ad_hoc_indexing(project)
          if ad_hoc_indexing_rate_limited?(project)
            logger.warn(
              build_structured_payload(
                message: "Ad-hoc indexing rate limited for namespace",
                project_id: project.id,
                namespace_id: project.root_namespace.id
              )
            )
            return :rate_limited
          end

          Ai::ActiveContext::Code::AdHocIndexingWorker.perform_async(project.id)
        rescue StandardError => e
          logger.warn(
            build_structured_payload(
              message: "Failed to trigger ad-hoc indexing",
              exception_class: e.class.name,
              exception_message: e.message,
              project_id: project.id
            )
          )

          false
        end

        def update_last_queried_timestamp(ac_repository)
          # Do not update if `last_queried_at` is nil, or it was updated within the set interval
          return if ac_repository.last_queried_at.present? &&
            ac_repository.last_queried_at > LAST_QUERIED_UPDATE_INTERVAL.ago

          ac_repository.update_last_queried_timestamp
        rescue ActiveRecord::ActiveRecordError => e
          logger.warn(
            build_structured_payload(
              message: "Failed to update last_queried_at",
              exception_class: e.class.name,
              exception_message: e.message,
              ai_active_context_code_repository_id: ac_repository.id,
              project_id: ac_repository.project_id
            )
          )
        end

        def prepare_hits(
          search_hits,
          project,
          exclude_fields: [],
          extract_source_segments: false,
          build_file_url: false
        )
          search_hits.map do |hit|
            item = hit.except(*exclude_fields)

            # The source is defined here:
            # https://gitlab.com/gitlab-org/gitlab-elasticsearch-indexer/-/blob/main/internal/mode/chunk/chunker/types.go
            # eg, fmt.Sprintf("%s::%d:%d::%d", c.OID, c.StartByte, c.Length, c.StartLine)
            if extract_source_segments
              src = hit['source']
              src_matched_segments = src.is_a?(String) && src.match(/\A([0-9a-f]{40})::(\d+):(\d+)::(\d+)\z/i)

              if src_matched_segments
                item['blob_id'] = src_matched_segments[1]
                item['start_byte'] = src_matched_segments[2].to_i
                item['length'] = src_matched_segments[3].to_i
                item['start_line'] = src_matched_segments[4].to_i
              end
            end

            if build_file_url
              item['file_url'] = Gitlab::Routing.url_helpers.project_blob_url(
                project, File.join(project.default_branch_or_main, item['path'])
              )
            end

            item
          end
        end

        def check_availability
          return if self.class.available?

          raise(
            NotAvailable,
            "Semantic search on Code collection is not available."
          )
        end

        # rubocop: disable CodeReuse/ActiveRecord -- no need to redefine a scope for the built-in method
        def find_active_context_repository(project_id)
          Ai::ActiveContext::Code::Repository.find_by(
            project_id: project_id,
            connection_id: collection_record.connection_id
          )
        end
        # rubocop: enable CodeReuse/ActiveRecord

        def repository_query(project_id, knn_count, limit)
          ::ActiveContext::Query.filter(
            project_id: project_id
          ).knn(
            target: search_embeddings_field,
            vector: target_embeddings,
            k: knn_count
          ).limit(
            limit
          )
        end

        def directory_query(project_id, path, knn_count, limit)
          ::ActiveContext::Query.and(
            ::ActiveContext::Query.filter(project_id: project_id),
            ::ActiveContext::Query.prefix(path: path_with_trailing_slash(path))
          ).knn(
            target: search_embeddings_field,
            vector: target_embeddings,
            k: knn_count
          ).limit(
            limit
          )
        end

        def path_with_trailing_slash(path)
          path.ends_with?("/") ? path : "#{path}/"
        end

        def target_embeddings
          @target_embeddings ||= generate_target_embeddings
        end

        def generate_target_embeddings
          search_embedding_model.generate_embeddings(search_term, user: user).first
        end

        def search_embedding_model
          @search_embedding_model ||= self.class.search_embedding_model
        end

        def search_embeddings_field
          search_embedding_model.field
        end

        def collection_record
          @collection_record ||= COLLECTION_CLASS.collection_record
        end
      end
    end
  end
end
