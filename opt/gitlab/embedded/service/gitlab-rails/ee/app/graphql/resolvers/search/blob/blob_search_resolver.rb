# frozen_string_literal: true

module Resolvers
  module Search
    module Blob
      class BlobSearchResolver < ::Resolvers::Search::BaseResolver
        calls_gitaly!
        include Gitlab::Graphql::Authorize::AuthorizeResource

        type Types::Search::Blob::BlobSearchType, null: true
        argument :chunk_count, type: GraphQL::Types::Int, required: false, experiment: { milestone: '17.2' },
          default_value: ::Search::Zoekt::MultiMatch::DEFAULT_REQUESTED_CHUNK_SIZE,
          description: 'Maximum chunks per file.'
        argument :exclude_forks, GraphQL::Types::Boolean, required: false, default_value: true,
          experiment: { milestone: '17.11' },
          description: 'Excludes forked projects in the search. Always false for project search. Default is true.'
        argument :group_id, ::Types::GlobalIDType[::Group], required: false, experiment: { milestone: '17.2' },
          description: 'Group to search in.'
        argument :include_archived, GraphQL::Types::Boolean, required: false, default_value: false,
          experiment: { milestone: '17.7' },
          description: 'Includes archived projects in the search. Always true for project search. Default is false.'
        argument :language, [GraphQL::Types::String], required: false, experiment: { milestone: '19.3' },
          validates: { length: { maximum: Types::BaseArgument::MAX_ARRAY_SIZE } },
          description: 'Filter results to the given detected languages (for example, `["Ruby", "Go"]`).'
        argument :page, type: GraphQL::Types::Int, required: false, default_value: 1, experiment: { milestone: '17.2' },
          description: 'Page number to fetch the results.'
        argument :per_page, type: GraphQL::Types::Int, required: false, experiment: { milestone: '17.2' },
          default_value: ::Search::Zoekt::SearchResults::DEFAULT_PER_PAGE, description: 'Number of results per page.'
        argument :project_id, ::Types::GlobalIDType[::Project], required: false, experiment: { milestone: '17.2' },
          description: 'Project to search in.'
        argument :regex, GraphQL::Types::Boolean, required: false, default_value: false,
          experiment: { milestone: '17.3' },
          description: 'Uses the regular expression search mode. Default is false.'
        argument :repository_ref, type: GraphQL::Types::String, required: false, experiment: { milestone: '17.2' },
          description: 'Repository reference to search in.'
        argument :search, GraphQL::Types::String, required: true, description: 'Searched term.'

        def resolve(**args)
          start_time = Time.current
          results(**args)
        ensure
          if ::Gitlab::SafeRequestStore.active?
            duration = Time.current - start_time - ::Gitlab::Instrumentation::Zoekt.zoekt_call_duration
            ::Gitlab::Instrumentation::Zoekt.add_call_details(
              duration: duration,
              method: context[:request].method,
              path: context[:request].path,
              body: context.query.provided_variables
            )
            ::Gitlab::Instrumentation::Zoekt.add_graphql_duration(duration)
          end
        end

        private

        def verify_additional_preconditions!(**args)
          verify_repository_ref!(args[:project_id]&.model_id, args[:repository_ref])
          @search_service = SearchService.new(current_user, search_params(**args))
          verify_global_search_is_allowed!
          verify_search_is_zoekt!
        end

        def verify_repository_ref!(project_id, ref)
          project = Project.find_by_id(project_id)
          return if project.nil? || ref.blank? || (project.default_branch == ref)

          raise Gitlab::Graphql::Errors::ArgumentError, 'Search is only allowed in project default branch'
        end

        def verify_global_search_is_allowed!
          return unless @search_service.level == 'global'
          return if @search_service.global_search_enabled_for_scope?

          raise Gitlab::Graphql::Errors::ArgumentError, 'Global search is not enabled for this scope'
        end

        def verify_search_is_zoekt!
          return if @search_service.search_type == 'zoekt'

          raise Gitlab::Graphql::Errors::ArgumentError, 'Zoekt search is not available for this request'
        end

        def results(**args)
          match_count = 0
          global_search_duration_s = Benchmark.realtime do
            @results = @search_service.search_objects unless count_only_operation?
            @search_results = @search_service.search_results
            match_count = @search_results.blobs_count
          end

          if @search_results.failed?
            raise Gitlab::Graphql::Errors::BaseError.new(
              @search_results.error,
              extensions: { error_type: @search_results.error_type&.name&.demodulize }
            )
          end

          Gitlab::Metrics::GlobalSearchSlis.record_apdex(
            elapsed: global_search_duration_s,
            search_type: @search_service.search_type,
            search_level: @search_service.level,
            search_scope: @search_service.scope,
            observe_duration: !count_only_operation?
          )

          # Only recording site for zoekt multi-match (SearchController#show skips
          # haml_search_results, so record_search_relevancy_counters never fires).
          # Skipped for count-only: a background scope-badge fetch, not a user search.
          unless count_only_operation?
            Gitlab::Metrics::GlobalSearchRelevancyCounters.record_search(
              search_type: @search_service.search_type,
              scope: @search_service.scope,
              zero_results: match_count == 0,
              source: 'graphql'
            )

            track_perform_search_event
          end

          {
            duration_s: global_search_duration_s,
            match_count: match_count,
            file_count: @search_results.file_count,
            search_level: @search_service.level,
            search_type: @search_service.search_type,
            per_page: args[:per_page],
            files: @results
          }
        ensure
          # gitlab_sli_global_search_* is an ErrorRate SLI: its denominator
          # (gitlab_sli_global_search_total) only advances when record_error_rate is called at
          # all. Recording only on failure would make this population's error ratio a constant
          # 100%, so this has to run on every exit path, success included.
          #
          # This is the only recording site for zoekt web exact code search:
          # EE::SearchController#multi_match? is true for scope=blobs + search_type=zoekt, so
          # SearchController#show skips haml_search_results and never calls record_search_error.
          record_error_rate
        end

        # error: true only for a genuine service failure: a nil result (the benchmark block
        # raised) or a Zoekt/backend server error. A failed? result that is not server_error?
        # (an invalid query, an abusive term) is the user's, so it belongs in the denominator
        # as a non-error, matching what the previous numerator-only condition counted.
        #
        # This runs from an ensure on every request, so a raise here would propagate out of the
        # ensure and replace whatever exception was already in flight -- including the
        # Gitlab::Graphql::Errors::BaseError raised above for an invalid regex or an abusive
        # term. Recording a metric must never change the response, so swallow and report
        # instead. track_and_raise_for_dev_exception still raises in development and test, so a
        # genuine labels mismatch is loud where we want it to be and silent in production.
        def record_error_rate
          Gitlab::Metrics::GlobalSearchSlis.record_error_rate(
            error: @search_results.nil? || @search_results.server_error?,
            search_type: @search_service.search_type,
            search_level: @search_service.level,
            search_scope: @search_service.scope
          )
        rescue StandardError => e
          Gitlab::ErrorTracking.track_and_raise_for_dev_exception(e)
        end

        def search_params(**args)
          {
            group_id: args[:group_id]&.model_id,
            project_id: args[:project_id]&.model_id,
            search: args[:search],
            page: args[:page],
            per_page: args[:per_page],
            chunk_count: args[:chunk_count],
            scope: scope,
            regex: args[:regex],
            include_archived: args[:include_archived],
            exclude_forks: args[:exclude_forks],
            language: args[:language]
          }
        end

        def scope
          'blobs'
        end

        def count_only_operation?
          context.query.operation_name == 'getBlobSearchCountQuery'
        end

        def track_perform_search_event
          Gitlab::InternalEvents.track_event(
            'perform_search',
            category: self.class.name,
            user: current_user,
            additional_properties: {
              label: @search_service.scope,
              search_type: @search_service.search_type,
              search_level: @search_service.level
            }
          )
        end
      end
    end
  end
end
