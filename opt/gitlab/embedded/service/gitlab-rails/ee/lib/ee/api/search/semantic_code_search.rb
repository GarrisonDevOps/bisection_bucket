# frozen_string_literal: true

module EE
  module API
    module Search
      class SemanticCodeSearch < ::API::Base # rubocop:disable Gitlab/EeOnlyClass -- standalone EE-only endpoint
        include ::API::APIGuard
        include ::API::Concerns::McpAccess

        helpers ::Ai::ActiveContext::Concerns::CodePostProcessing
        helpers ::EE::API::Helpers::McpHelpers

        feature_category :global_search
        urgency :low

        REST_API_TRANSPORT = 'rest_api'
        MCP_TRANSPORT = 'mcp'
        BACKEND_TIMEOUT_RETRY_AFTER_SECONDS = 30

        allow_access_with_scope :ai_workflows, if: ->(request) { request.get? || request.head? }
        allow_mcp_access_read

        before do
          authenticate!
          check_rate_limit!(
            :semantic_search_rate_limit,
            scope: { user: current_user }
          )
        end

        rescue_from ::Ai::ActiveContext::Queries::Code::NotAvailable do
          not_found!('Semantic code search is not available')
        end

        rescue_from ::Gitlab::Llm::Concerns::ExponentialBackoff::RateLimitError do
          too_many_requests!('Semantic code search is temporarily rate limited by the AI Gateway, ' \
            'please try again later')
        end

        rescue_from ::Elastic::TimeoutError, ::Faraday::TimeoutError, ::Net::ReadTimeout do
          header 'Retry-After', BACKEND_TIMEOUT_RETRY_AFTER_SECONDS.to_s
          service_unavailable!('Semantic code search backend timed out, please try again later')
        end

        helpers do
          def validate_directory_path!
            dir_path = params[:directory_path]
            return unless dir_path
            return unless dir_path.start_with?('/') || dir_path.split('/').include?('..')

            bad_request!('directory_path must not start with / or contain .. segments')
          end

          def execute_semantic_search
            ::Ai::ActiveContext::Queries::Code
              .new(search_term: params[:q], user: current_user)
              .filter(
                project_or_id: user_project,
                path: params[:directory_path],
                knn_count: params[:knn],
                limit: params[:limit],
                exclude_fields: %w[id source type embeddings_v1 reindexing],
                extract_source_segments: true,
                build_file_url: true
              )
          rescue ::Ai::ActiveContext::Queries::Code::NotAvailable
            # Instance-wide configuration state, not a service failure: as an error it would
            # burn the error budget of an unconfigured instance, as a success it would report
            # healthy while the endpoint serves 100% 404s.
            exclude_from_sli!

            raise
          end

          def reject_project_without_embeddings!(result)
            return if result.success?

            # Client-side condition, and no search was timed; excluded so apdex and error rate
            # keep the same denominator.
            exclude_from_sli!

            unprocessable_entity!(
              result.error_message(target_class: 'Project', target_id: user_project.id)
            )
          end

          def track_semantic_search_event(confidence, grouped)
            ::Gitlab::InternalEvents.track_event(
              'search_code_with_semantic_search',
              user: current_user,
              project: user_project,
              namespace: user_project.root_namespace,
              additional_properties: {
                label: confidence.to_s,
                property: semantic_search_transport,
                value: grouped.size
              }
            )
          end

          def start_sli_observation!
            @sli_started_at = ::Gitlab::Metrics::System.monotonic_time
            @sli_search_failed = false
          end

          # Requests rejected before a search is attempted must not reach the SLI denominator.
          def exclude_from_sli!
            @sli_started_at = nil
          end

          def mark_sli_failure!
            @sli_search_failed = true
          end

          def observing_sli?
            @sli_started_at.present?
          end

          def record_semantic_search_apdex
            ::Gitlab::Metrics::GlobalSearchSlis.record_apdex(
              elapsed: ::Gitlab::Metrics::System.monotonic_time - @sli_started_at,
              **semantic_search_sli_labels
            )
          end

          def record_semantic_search_error_rate
            ::Gitlab::Metrics::GlobalSearchSlis.record_error_rate(
              error: @sli_search_failed,
              **semantic_search_sli_labels
            )
          end

          def semantic_search_sli_labels
            {
              search_type: ::Gitlab::Metrics::GlobalSearchSlis::SEMANTIC_SEARCH_TYPE,
              search_level: ::Gitlab::Metrics::GlobalSearchSlis::SEMANTIC_SEARCH_LEVEL,
              search_scope: ::Gitlab::Metrics::GlobalSearchSlis::SEMANTIC_SEARCH_SCOPE
            }
          end

          # Labelled by token scope; a GRANULAR_SCOPE-only token also reaches MCP but reads as 'rest_api'.
          def semantic_search_transport
            mcp_request? ? SemanticCodeSearch::MCP_TRANSPORT : SemanticCodeSearch::REST_API_TRANSPORT
          end
        end

        resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
          route_setting :lifecycle, :beta
          route_setting :authorization, permissions: :read_code, boundary_type: :project
          route_setting :mcp,
            tool_name: :semantic_code_search,
            params: [:id, :q, :directory_path, :knn, :limit],
            annotations: { readOnlyHint: true },
            resource_name: "project",
            aggregators: [::Mcp::Tools::SemanticSearch::SemanticSearchService]
          desc 'Search project code using natural language' do
            detail <<~DETAIL
              Introduced in GitLab 18.11.

              Searches indexed project code using semantic (meaning-based) similarity rather than
              keyword matching. Use this when you do not know the exact symbol or file name, or
              to discover how a behavior is implemented across the codebase.

              Primary use cases:
              - When you do not know the exact symbol or file path
              - To see how a behavior or feature is implemented across the codebase
              - To discover related implementations (clients, jobs, workers)

              How to use:
              - Provide a concise, specific query with concrete keywords
              - Use directory_path to narrow scope (e.g. "app/services/")
              - Prefer precise intent over broad terms

              Results are grouped by file. Each file includes merged line ranges with content
              and a relevance score (0.0-1.0). The response includes an overall confidence
              level (high/medium/low/unknown) based on score distribution. Results are
              filtered by Duo context exclusion settings.

              Requires semantic code search to be enabled and indexed for the project namespace.
            DETAIL
            tags %w[search]
            success code: 200, model: ::API::Entities::Ai::SemanticCode::Response
            failure [
              { code: 401, message: 'Unauthorized' },
              { code: 403, message: 'Forbidden' },
              { code: 404, message: 'Not found - project not found or semantic code search unavailable' },
              { code: 422, message: 'Unprocessable entity - project has no embeddings' },
              { code: 429, message: 'Too many requests' },
              { code: 503, message: 'Service unavailable - search backend timed out' }
            ]
          end
          params do
            requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
            requires :q, type: String, limit: 1000, allow_blank: false,
              desc: 'Natural language search query, for example `authentication middleware` or `rate limiting logic`.'
            optional :directory_path, type: String, limit: 100,
              desc: 'Restrict search to files under this directory path, for example `app/services/`. Must be a ' \
                'relative path with no leading slash and no `..` segments.'
            optional :knn, type: Integer, values: 1..100,
              default: ::Ai::ActiveContext::Queries::Code::KNN_COUNT,
              desc: 'Number of nearest neighbours to retrieve internally ' \
                "(default: #{::Ai::ActiveContext::Queries::Code::KNN_COUNT}). " \
                'Higher values improve recall at the cost of latency.'
            optional :limit, type: Integer, values: 1..100,
              default: ::Ai::ActiveContext::Queries::Code::SEARCH_RESULTS_LIMIT,
              desc: 'Maximum number of results to return ' \
                "(default: #{::Ai::ActiveContext::Queries::Code::SEARCH_RESULTS_LIMIT})."
          end
          get ':id/(-/)search/semantic' do
            authorize! :read_code, user_project
            validate_directory_path!

            start_sli_observation!

            result = execute_semantic_search
            reject_project_without_embeddings!(result)

            filtered = filter_excluded_results(result.to_a, user_project)
            grouped = group_results_by_file(filtered)
            confidence = compute_confidence_level(extract_scores(filtered))

            record_semantic_search_apdex

            track_semantic_search_event(confidence, grouped)

            present(
              { confidence: confidence.to_s, results: grouped },
              with: ::API::Entities::Ai::SemanticCode::Response
            )
          rescue StandardError
            # Grape's error! throws :error rather than raising, so the bang helpers above never
            # reach here; anything that does is a real service failure, including `present`.
            mark_sli_failure!

            raise
          ensure
            record_semantic_search_error_rate if observing_sli?
          end
        end
      end
    end
  end
end
