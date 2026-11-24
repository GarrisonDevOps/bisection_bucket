# frozen_string_literal: true

module EE
  module API
    module Search
      ADVANCED_SEARCH_TYPE = 'advanced'
      EXACT_CODE_SEARCH_TYPE = 'zoekt'
      ADVANCED_SEARCH_SCOPES = %w[blobs commits notes wiki_blobs].freeze
      FIELDS_SUPPORTED_SCOPES = %w[issues merge_requests].freeze
      MR_FILTER_PARAMS = %i[source_branch target_branch author_username label_name].freeze
      MR_FILTER_NEGATABLE_PARAMS = %i[source_branch target_branch author_username].freeze
      # A filter supplied outside its listed scopes is refused, not forwarded and dropped.
      MR_FILTER_SCOPES = {
        source_branch: %w[merge_requests],
        target_branch: %w[merge_requests],
        author_username: %w[issues merge_requests work_items],
        label_name: %w[issues merge_requests work_items]
      }.freeze
      BLOB_SEARCH_TYPES = %W[#{ADVANCED_SEARCH_TYPE} #{EXACT_CODE_SEARCH_TYPE}].freeze
      BLOB_SEARCH_PARAM_RULES = {
        regex:
          { valid_types: %W[#{EXACT_CODE_SEARCH_TYPE}],
            message: 'regex supported only with exact code search' },
        exclude_forks:
          { valid_types: %W[#{EXACT_CODE_SEARCH_TYPE}],
            message: 'exclude_forks supported only with exact code search' },
        num_context_lines:
          { valid_types: BLOB_SEARCH_TYPES,
            message: 'num_context_lines supported only with advanced and exact code search' }
      }.freeze

      extend ActiveSupport::Concern

      prepended do
        # Mirrors EE::SearchController: report the timeout as 408, not 500.
        # This specific handler pre-empts Grape's rescue_from :all, so
        # handle_api_exception never runs and must be tracked explicitly.
        rescue_from ::Elastic::TimeoutError do |e|
          ::Gitlab::ErrorTracking.track_exception(e)

          render_api_error!('Request timed out', 408)
        end

        helpers do
          include ::API::Helpers::SearchHelpers
          include Helpers::McpHelpers
          extend ::Gitlab::Utils::Override

          params :ee_param_fields do
            optional :fields, type: Array[String], coerce_with: ::API::Validations::Types::CommaSeparatedToArray.coerce,
              values: %w[title], desc: 'Fields to search. Supports only `issues` and `merge_requests` scopes. ' \
                                   'Premium and Ultimate only.'
          end

          params :ee_param_exclude_forks do
            optional :exclude_forks, type: Grape::API::Boolean,
              desc: 'If `true`, excludes forked projects from the search. If omitted, forks are excluded. ' \
                'Available for exact code search. ' \
                '[Introduced](https://gitlab.com/gitlab-org/gitlab/-/work_items/493281) in GitLab ' \
                '18.7.' # rubocop:disable Layout/LineLength,Lint/RedundantCopDisableDirective -- keep readability
          end

          params :ee_param_num_context_lines do
            optional :num_context_lines, type: Integer,
              values: 0..::Gitlab::Elastic::SearchResults::MAX_NUM_CONTEXT_LINES,
              desc: 'Number of context lines to include around each match in the results. Available for ' \
                'advanced and exact code search only. ' \
                '[Introduced](https://gitlab.com/gitlab-org/gitlab/-/work_items/583217) in GitLab ' \
                '18.11.' # rubocop:disable Layout/LineLength,Lint/RedundantCopDisableDirective -- keep readability
          end

          params :ee_param_regex do
            optional :regex, type: Grape::API::Boolean,
              desc: 'If `true`, uses regular expressions to search for code. If omitted, regular expressions are ' \
                'used. Available for exact code search. ' \
                '[Introduced](https://gitlab.com/gitlab-org/gitlab/-/work_items/521686) in GitLab 18.9.'
          end

          params :ee_param_mr_filters do
            optional :source_branch, type: String,
              desc: 'Filter merge requests by source branch. Available with advanced search and the merge_requests scope.' # rubocop:disable Layout/LineLength,Lint/RedundantCopDisableDirective -- keep readability
            optional :target_branch, type: String,
              desc: 'Filter merge requests by target branch. Available with advanced search and the merge_requests scope.' # rubocop:disable Layout/LineLength,Lint/RedundantCopDisableDirective -- keep readability
            optional :author_username, type: String,
              desc: 'Filter by author username. A username that matches no user is ignored. Available with advanced search and the issues, merge_requests and work_items scopes.' # rubocop:disable Layout/LineLength,Lint/RedundantCopDisableDirective -- keep readability
            # Honoured by the deprecated `Filters#by_label_ids`; its replacement `by_label_names`
            # reads `label_names`, so migrating a scope must map this key or stop filtering.
            optional :label_name, type: Array[String], limit: 30,
              coerce_with: ::API::Validations::Types::CommaSeparatedToArray.coerce,
              desc: 'Filter by label name. A result must carry every name that resolves to an existing label; names that match no label are ignored. Maximum 30 names. Available with advanced search and the issues, merge_requests and work_items scopes.' # rubocop:disable Layout/LineLength,Lint/RedundantCopDisableDirective -- keep readability
            optional :not, type: Hash,
              desc: 'Filter out results matching the parameters supplied. Supplying a filter together with its negation matches either condition, which widens the result set.' do # rubocop:disable Layout/LineLength,Lint/RedundantCopDisableDirective -- keep readability
              optional :source_branch, type: String, desc: 'Exclude merge requests with this source branch'
              optional :target_branch, type: String, desc: 'Exclude merge requests with this target branch'
              optional :author_username, type: String, desc: 'Exclude results authored by this username'
            end
          end

          override :search
          def search(additional_params = {})
            # For MCP requests, gracefully return empty results when all types unavailable
            # For non-MCP requests, fall through to CE which returns bad_request
            return Kaminari.paginate_array([]) if unavailable_work_item_types? && mcp_request?

            super
          rescue ::Gitlab::Search::Client::ConnectionError, ::Gitlab::Search::Client::AuthorizationError => e
            render_api_error!(e.message, 503)
          end

          override :scope_preload_method
          def scope_preload_method
            super.merge(blobs: :with_api_blob_entity_associations).freeze
          end

          # do not use this method for project search API
          # all search scopes allowed for project level search
          override :verify_search_scope_for_ee!
          def verify_search_scope_for_ee!(search_type)
            scope = user_requested_search_scope
            return if scope == 'blobs' && BLOB_SEARCH_TYPES.include?(search_type)
            return if ADVANCED_SEARCH_SCOPES.exclude?(scope) || search_type == ADVANCED_SEARCH_TYPE

            render_api_error!(scope_error_message(scope), 400)
          end

          def scope_error_message(scope)
            return 'Scope supported only with advanced search or exact code search' if scope == 'blobs'

            'Scope supported only with advanced search'
          end

          override :verify_ee_blob_search_params!
          def verify_ee_blob_search_params!(search_type)
            return if mcp_request?

            BLOB_SEARCH_PARAM_RULES.each do |param, rule|
              next unless params.key?(param)
              next if rule[:valid_types].include?(search_type)

              render_api_error!(rule[:message], 400)
            end
          end

          override :verify_ee_param_fields!
          def verify_ee_param_fields!(search_type)
            return unless params.key?(:fields)
            return if mcp_request?

            if FIELDS_SUPPORTED_SCOPES.exclude?(user_requested_search_scope)
              render_api_error!("fields is supported only for #{FIELDS_SUPPORTED_SCOPES.join(', ')}", 400)
            end

            return if search_type == ADVANCED_SEARCH_TYPE

            render_api_error!("fields is supported only for #{ADVANCED_SEARCH_TYPE} search", 400)
          end

          override :verify_ee_param_mr_filters!
          def verify_ee_param_mr_filters!(search_type)
            # No `return if mcp_request?`: that would serve an MCP caller an unfiltered 200.
            verify_negated_mr_filter_keys!

            supplied = supplied_mr_filter_params
            return if supplied.empty?

            scope = user_requested_search_scope
            unsupported = supplied.reject { |_name, key| MR_FILTER_SCOPES.fetch(key).include?(scope) }
            render_api_error!(unsupported_scope_message(unsupported), 400) if unsupported.any?

            return if search_type == ADVANCED_SEARCH_TYPE

            render_api_error!(
              "#{filter_names(supplied)} is supported only for #{ADVANCED_SEARCH_TYPE} search", 400
            )
          end

          # `negated_search_params` drops an undeclared sub-key, so accepting one
          # would answer 200 over the unfiltered set.
          def verify_negated_mr_filter_keys!
            return unless params[:not].respond_to?(:keys)

            undeclared = params[:not].keys.map(&:to_sym) - MR_FILTER_NEGATABLE_PARAMS
            return if undeclared.empty?

            render_api_error!(
              "#{undeclared.map { |key| "not[#{key}]" }.join(', ')} is not a supported filter", 400
            )
          end

          # Names each filter as the CLIENT sent it; the flattened `not_source_branch`
          # must never reach a response.
          def supplied_mr_filter_params
            positive = MR_FILTER_PARAMS.filter_map { |key| [key.to_s, key] if params.key?(key) }
            negated = MR_FILTER_NEGATABLE_PARAMS
              .filter_map do |key|
                ["not[#{key}]", key] if params[:not].respond_to?(:key?) && params[:not].key?(key)
              end

            positive + negated
          end

          def unsupported_scope_message(unsupported)
            unsupported
              .group_by { |_name, key| MR_FILTER_SCOPES.fetch(key) }
              .map { |scopes, filters| "#{filter_names(filters)} is supported only for #{scopes.join(', ')}" }
              .join('; ')
          end

          def filter_names(filters)
            filters.map(&:first).join(', ')
          end
        end
      end
    end
  end
end
