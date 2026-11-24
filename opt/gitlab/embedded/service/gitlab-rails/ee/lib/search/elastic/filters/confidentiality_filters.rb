# frozen_string_literal: true

module Search
  module Elastic
    module Filters
      module ConfidentialityFilters
        extend ActiveSupport::Concern

        class_methods do
          include ::Elastic::Latest::QueryContext::Aware
          include Search::Elastic::Concerns::FilterUtils
          include Search::Elastic::Concerns::AuthorizationUtils

          # Applies combined confidentiality filters for both project and group level resources.
          # This method orchestrates the application of confidentiality filters, allowing for
          # authorization checks at both the project and group levels. It uses `BoolExpr`
          # to combine the results of project and group confidentiality filters with a `should`
          # clause, meaning a resource is accessible if it passes either the project or group
          # level authorization.
          #
          # @param query_hash [Hash] The Elasticsearch query hash to which filters will be added.
          # @param options [Hash] A hash of options controlling the filtering behavior.
          #
          # @option options [Boolean] :use_project_authorization (false) If `true`, project-level
          #   confidentiality filters will be applied.
          # @option options [Boolean] :use_group_authorization (false) If `true`, group-level
          #   confidentiality filters will be applied.
          # @option options [Hash] :features A hash of project features used in authorization.
          #   Used to check `<feature>_access_level`. This key is removed for group confidentiality filters.
          # @option options [Array<Symbol>] :filter_path ([:query, :bool, :filter]) The path within the
          #   `query_hash` where the generated filter should be inserted.
          #
          # @return [Hash] The modified `query_hash` with combined confidentiality filters applied.
          #
          # @note This method assumes that `by_project_confidentiality` and `by_group_level_confidentiality`
          #   are defined and handle their respective filtering logic.
          def by_combined_confidentiality(query_hash:, options:)
            combined_filter = Search::Elastic::BoolExpr.new

            if options[:use_project_authorization]
              add_filter(combined_filter, :should) do
                project_filter = Search::Elastic::BoolExpr.new
                project_options = options.merge(filter_path: [:filter])

                by_project_confidentiality(query_hash: project_filter, options: project_options)

                project_filter.to_bool_query
              end
            end

            if options[:use_group_authorization]
              add_filter(combined_filter, :should) do
                group_filter = Search::Elastic::BoolExpr.new
                group_options = options.merge(filter_path: [:filter])
                # group authorization for confidentiality uses min_access_level
                # `features` is only needed for the project confidentiality so remove it for group checks
                group_options.delete(:features)

                by_group_level_confidentiality(query_hash: group_filter, options: group_options)

                group_filter.to_bool_query
              end
            end

            add_filter(query_hash, :query, :bool, :filter) do
              combined_filter.to_bool_query
            end
          end

          # Applies confidentiality filters for project-level resources.
          #
          # This method constructs an Elasticsearch query to filter project-level resources
          # based on their confidentiality status and the current user's access permissions.
          # It supports both legacy and new (traversal IDs based) filtering mechanisms.
          #
          # @param query_hash [Hash] The Elasticsearch query hash to which filters will be added.
          # @param options [Hash] A hash of options controlling the filtering behavior.
          #
          # @option options [Boolean] :confidential (nil) If `true`, only confidential resources are returned.
          #   If `false`, only non-confidential resources are returned. If `nil`, both are considered,
          #   and access rules are applied.
          # @option options [User] :current_user The user for whom the confidentiality filters are applied.
          #   If `nil`, only public non-confidential resources are accessible.
          # @option options [Array<Integer>] :project_ids (nil) An array of project IDs to scope the search.
          # @option options [Array<Integer>] :group_ids (nil) An array of group IDs to scope the search.
          # @option options [Array<Symbol>] :filter_path ([:query, :bool, :filter]) The path within the
          #   `query_hash` where the generated filter should be inserted.
          # @option options [Integer] :min_access_level_confidential The minimum access level required
          #   to view confidential resources. Defaults to `Gitlab::Access::PLANNER`.
          # @option options [String] :project_id_field ('project_id') The field name in Elasticsearch
          #   documents that stores the project ID.
          # @option options [String] :traversal_ids_prefix ('traversal_ids') The field name prefix in
          #   Elasticsearch documents that stores traversal IDs for ancestry.
          #
          # @return [Hash] The modified `query_hash` with confidentiality filters applied.
          def by_project_confidentiality(query_hash:, options:)
            filter_context = ConfidentialityFilterContext.new(options)

            context.name(:filters, :confidentiality, :projects) do
              apply_user_confidentiality_filter(query_hash, filter_context)

              next query_hash if filter_context.auth.admin_user?
              next query_hash if filter_context.non_confidential_only?

              auth_data = prepare_project_authorization_data(options, filter_context)
              apply_confidentiality_access_filters(query_hash, filter_context, auth_data)
            end
          end

          # Applies confidentiality filters for group-level resources.
          # This method constructs an Elasticsearch query to filter group-level resources
          #
          # @option options [Array<Symbol>] :filter_path ([:query, :bool, :filter]) The path within the
          #   `query_hash` where the generated filter should be inserted.
          #   to view confidential resources.
          # @option options [Array<Integer>] :group_ids (nil) An array of group IDs to scope the search.
          # @option options [Integer] :min_access_level_confidential The minimum access level required
          #   to view confidential resources. Defaults to `Gitlab::Access::PLANNER`.
          # @option options [String] :project_id_field ('project_id') The field name in Elasticsearch
          #   documents that stores the project ID.
          # @option options [String] :traversal_ids_prefix ('traversal_ids') The field name prefix in
          #   Elasticsearch documents that stores traversal IDs for ancestry.
          #
          # @return [Hash] The modified `query_hash` with confidentiality filters applied.
          def by_group_level_confidentiality(query_hash:, options:)
            filter_context = ConfidentialityFilterContext.new(options)

            context.name(:filters, :confidentiality, :groups) do
              apply_user_confidentiality_filter(query_hash, filter_context)

              next query_hash if filter_context.auth.admin_user?
              next query_hash if filter_context.non_confidential_only?

              auth_data = prepare_group_authorization_data(options, filter_context)
              apply_confidentiality_access_filters(query_hash, filter_context, auth_data)
            end
          end

          # Applies confidentiality filters for notes.
          # Notes have two levels of confidentiality:
          # 1. Note's own confidentiality (`confidential` field)
          # 2. Issue's confidentiality (`issue.confidential`, `issue.author_id`, `issue.assignee_id`)
          #
          # A note is visible if ANY of these conditions are met:
          # - It's on a non-confidential issue AND the note isn't confidential
          # - It's on a confidential issue but user is author/assignee/has project access
          # - The note is confidential but user has project access
          #
          # @param query_hash [Hash] The Elasticsearch query hash to which filters will be added.
          # @param options [Hash] A hash of options controlling the filtering behavior.
          # @return [Hash] The modified `query_hash` with note confidentiality filters applied.
          def by_note_confidentiality(query_hash:, options:)
            note_filter_context = ConfidentialityFilterContext.new(options)
            return query_hash if note_filter_context.auth.admin_user?

            context.name(:filters, :confidentiality, :notes) do
              # issue_filter_context remaps field accessors to issue.* nested fields
              issue_filter_context = ConfidentialityFilterContext.new(options.merge(
                confidential_field: 'issue.confidential',
                author_id_field: 'issue.author_id',
                assignee_id_field: 'issue.assignee_id'))

              bool_expr = Search::Elastic::BoolExpr.new

              add_filter(bool_expr, :should) do
                build_non_confidential_note_filter(issue_filter_context, note_filter_context)
              end

              unless note_filter_context.auth.anonymous_user?
                auth_data = prepare_project_authorization_data(options, note_filter_context)

                add_filter(bool_expr, :should) do
                  build_confidential_issue_and_non_confidential_note_filter(auth_data, issue_filter_context,
                    note_filter_context)
                end

                add_filter(bool_expr, :should) do
                  build_confidential_note_filter(auth_data, note_filter_context)
                end
              end

              add_filter(query_hash, :query, :bool, :filter) do
                bool_expr.to_bool_query
              end
            end
          end

          private

          def apply_user_confidentiality_filter(query_hash, filter_context)
            return query_hash unless filter_context.confidential_filter_specified?

            if filter_context.auth.anonymous_user? && filter_context.confidential_only?
              add_filter(query_hash, *filter_context.filter_path) do
                { match_none: { _name: context.name(:anonymous_user_confidential_filter_not_allowed) } }
              end

              return
            end

            add_filter(query_hash, *filter_context.filter_path) do
              { term:
                { filter_context.confidential_field =>
                  { _name: context.name(:user_filter),
                    value: filter_context.confidential } } }
            end
          end

          def prepare_project_authorization_data(options, filter_context)
            return {} if filter_context.auth.anonymous_user?

            level_for_private = filter_context.min_access_level_confidential
            level_for_not_private = filter_context.min_access_level_confidential_public_internal

            private_projects = filter_context.auth.get_projects_for_user(
              options.merge(min_access_level: level_for_private))
            public_internal_projects = filter_context.auth.get_projects_for_user(
              options.merge(min_access_level: level_for_not_private))

            private_groups = filter_context.auth.get_groups_for_user(min_access_level: level_for_private)
            private_traversal_ids = filter_context.auth.get_formatted_traversal_ids_for_groups(
              private_groups, options.merge(min_access_level: level_for_private))

            public_internal_groups = filter_context.auth.get_groups_for_user(min_access_level: level_for_not_private)
            public_internal_traversal_ids = filter_context.auth.get_formatted_traversal_ids_for_groups(
              public_internal_groups, options.merge(min_access_level: level_for_not_private))

            # Remove duplicates only if levels are different
            if level_for_private != level_for_not_private
              public_internal_traversal_ids -= private_traversal_ids
              public_internal_projects = public_internal_projects.id_not_in(private_projects.select(:id))
            end

            {
              private_traversal_ids: private_traversal_ids,
              private_projects: private_projects,
              public_internal_traversal_ids: public_internal_traversal_ids,
              public_internal_projects: public_internal_projects
            }
          end

          def add_private_filters(confidential_filter, filter_context, auth_data)
            return if auth_data[:private_projects].blank? && auth_data[:private_traversal_ids].blank?

            context.name(:private) do
              add_filter(confidential_filter, :should) do
                build_project_authorization_filter(auth_data[:private_projects], filter_context)
              end

              add_filter(confidential_filter, :should) do
                build_traversal_authorization_filter(auth_data[:private_traversal_ids], filter_context)
              end
            end
          end

          def apply_confidentiality_access_filters(query_hash, filter_context, auth_data)
            # anonymous users can only see non-confidential data
            # membership filter will handle the authorization and role checks
            if filter_context.auth.anonymous_user?
              add_filter(query_hash, *filter_context.filter_path) do
                build_non_confidential_filter(filter_context)
              end

              return query_hash
            end

            if filter_context.confidential_only?
              # reduce query nesting when confidential filter is selected
              add_filter(query_hash, *filter_context.filter_path) do
                build_confidential_access_filter(filter_context, auth_data)
              end
            else
              bool_expr = ::Search::Elastic::BoolExpr.new

              add_filter(bool_expr, :should) do
                build_non_confidential_filter(filter_context)
              end

              add_filter(bool_expr, :should) do
                build_confidential_access_filter(filter_context, auth_data)
              end

              add_filter(query_hash, *filter_context.filter_path) do
                bool_expr.to_bool_query
              end
            end

            query_hash
          end

          def build_confidential_access_filter(filter_context, auth_data)
            confidential_filter = ::Search::Elastic::BoolExpr.new

            add_confidential_term_filter(confidential_filter, filter_context)
            add_assignee_filter(confidential_filter, filter_context)
            add_author_filter(confidential_filter, filter_context, auth_data)
            add_private_filters(confidential_filter, filter_context, auth_data)

            confidential_filter.to_bool_query
          end

          def prepare_group_authorization_data(options, filter_context)
            return {} if filter_context.auth.anonymous_user?

            private_traversal_ids = get_group_and_project_traversal_ids(filter_context,
              options.merge(min_access_level: filter_context.min_access_level_confidential))

            public_internal_traversal_ids = get_group_and_project_traversal_ids(filter_context,
              options.merge(min_access_level: filter_context.min_access_level_confidential_public_internal))
            public_internal_traversal_ids -= private_traversal_ids

            {
              private_traversal_ids: private_traversal_ids,
              public_internal_traversal_ids: public_internal_traversal_ids
            }
          end

          def get_group_and_project_traversal_ids(filter_context, auth_options)
            groups = filter_context.auth.get_groups_for_user(auth_options)
            traversal_ids = filter_context.auth.get_traversal_ids_for_search_level(groups, auth_options)
            trie = ::Namespaces::Traversal::TrieNode.build(traversal_ids)

            projects = filter_context.auth.get_projects_for_user(auth_options)
            namespaces_for_projects = Namespace.id_in(projects.select(:namespace_id))
            project_traversal_ids = namespaces_for_projects.map(&:traversal_ids).reject do |s|
              trie.covered?(s)
            end

            combined_traversal_ids = traversal_ids + project_traversal_ids
            format_traversal_ids(combined_traversal_ids.uniq)
          end

          def add_confidential_term_filter(confidential_filter, filter_context)
            return if filter_context.confidential_only?

            add_filter(confidential_filter, :filter) do
              build_confidential_filter(filter_context)
            end
          end

          def add_assignee_filter(confidential_filter, filter_context)
            add_filter(confidential_filter, :should) do
              build_assignee_filter(filter_context)
            end
          end

          def add_author_filter(confidential_filter, filter_context, auth_data)
            add_filter(confidential_filter, :should) do
              auth_expr = Search::Elastic::BoolExpr.new

              add_filter(auth_expr, :filter) do
                build_author_filter(filter_context)
              end

              add_filter(auth_expr, :should) do
                build_project_authorization_filter(auth_data[:public_internal_projects], filter_context)
              end

              add_filter(auth_expr, :should) do
                build_traversal_authorization_filter(auth_data[:public_internal_traversal_ids], filter_context)
              end

              add_filter(auth_expr, :should) do
                build_non_private_visibility_filter
              end

              auth_expr.to_bool_query
            end
          end

          def build_author_filter(filter_context)
            { term: { filter_context.author_id_field => { _name: context.name(:confidential, :as_author),
                                                          value: filter_context.user.id } } }
          end

          def build_assignee_filter(filter_context)
            { term: { filter_context.assignee_id_field => { _name: context.name(:confidential, :as_assignee),
                                                            value: filter_context.user.id } } }
          end

          def build_confidential_filter(filter_context)
            { term: { filter_context.confidential_field => { _name: context.name(:confidential), value: true } } }
          end

          def build_non_private_visibility_filter
            bool_expr = Search::Elastic::BoolExpr.new
            add_filter(bool_expr, :must_not) do
              { term: { namespace_visibility_level: ::Gitlab::VisibilityLevel::PRIVATE } }
            end

            bool_expr.to_bool_query
          end

          def build_traversal_authorization_filter(traversal_ids, filter_context)
            return if traversal_ids.blank?

            auth_expr = Search::Elastic::BoolExpr.new
            add_filter(auth_expr, :should) do
              ancestry_filter(traversal_ids, traversal_id_field: filter_context.traversal_ids_field)
            end

            auth_expr.to_bool_query
          end

          def build_project_authorization_filter(projects, filter_context)
            return if projects.blank?

            {
              terms: {
                _name: context.name(:project, :member),
                "#{filter_context.project_id_field}": projects.pluck_primary_key
              }
            }
          end

          def build_non_confidential_filter(filter_context)
            {
              term: { filter_context.confidential_field => { _name: context.name(:non_confidential), value: false } }
            }
          end

          def build_non_confidential_note_filter(issue_filter_context, note_filter_context)
            bool_expr = Search::Elastic::BoolExpr.new

            add_filter(bool_expr, :filter) do
              {
                bool: {
                  _name: context.name(:not_on_issue_or_not_confidential),
                  should: [
                    { bool: { _name: context.name(:not_on_issue), must_not: [{ exists: { field: "issue" } }] } },
                    { term: { issue_filter_context.confidential_field =>
                      { _name: context.name(:non_confidential_issue), value: false } } }
                  ]
                }
              }
            end

            add_filter(bool_expr, :filter) do
              build_non_confidential_notable_filter(note_filter_context)
            end

            bool_expr.to_bool_query
          end

          def build_non_confidential_notable_filter(filter_context)
            {
              bool: {
                _name: context.name(:not_confidential),
                should: [
                  { bool: { must_not: [{ exists: { field: filter_context.confidential_field.to_s } }] } },
                  { term: { filter_context.confidential_field => false } }
                ]
              }
            }
          end

          def build_confidential_issue_and_non_confidential_note_filter(
            auth_data, issue_filter_context,
            note_filter_context)
            bool_expr = Search::Elastic::BoolExpr.new

            add_filter(bool_expr, :filter) do
              { term: {
                issue_filter_context.confidential_field =>
                  { value: true, _name: context.name(:issue, :confidential) }
              } }
            end

            add_filter(bool_expr, :filter) do
              build_non_confidential_notable_filter(note_filter_context)
            end

            add_filter(bool_expr, :filter) do
              auth_expr = Search::Elastic::BoolExpr.new

              add_filter(auth_expr, :should) do
                build_author_filter(issue_filter_context)
              end

              add_filter(auth_expr, :should) do
                build_assignee_filter(issue_filter_context)
              end

              add_private_filters(auth_expr, note_filter_context, auth_data)

              auth_expr.to_bool_query
            end

            bool_expr.to_bool_query
          end

          def build_confidential_note_filter(auth_data, filter_context)
            return if auth_data[:private_projects].blank? && auth_data[:private_traversal_ids].blank?

            confidential_filter = Search::Elastic::BoolExpr.new

            add_confidential_term_filter(confidential_filter, filter_context)
            add_private_filters(confidential_filter, filter_context, auth_data)

            confidential_filter.to_bool_query
          end
        end
      end
    end
  end
end
