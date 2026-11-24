# frozen_string_literal: true

module Ai
  module Governance
    class SessionsFinder
      include ::Gitlab::Utils::StrongMemoize

      # @param current_user [User]
      # @param namespace [Namespace] group, or the project namespace for a project-scoped listing
      # @param params [Hash] filters, see {#apply_filters}
      def initialize(current_user:, namespace:, params: {})
        @current_user = current_user
        @namespace = namespace
        @params = params
      end

      # Returns sessions in the namespace and its descendants, newest first.
      #
      # @return [ActiveRecord::Relation<Ai::Governance::Session>]
      def execute
        return ::Ai::Governance::Session.none unless allowed?

        # An id matches at most one row, so a plain lookup is far cheaper than walking every namespace.
        return id_lookup if params[:id].present?

        # Walks i_ai_governance_sessions_on_namespace_started_at_id once per namespace in the hierarchy.
        # Filters on other columns are checked row by row during the walk, so a selective one can read
        # far more than one page. See https://docs.gitlab.com/development/database/efficient_in_operator_queries
        ::Gitlab::Pagination::Keyset::InOperatorOptimization::QueryBuilder.new(
          scope: apply_filters(
            ::Ai::Governance::Session.order_by_session_started_at_and_id_desc.without_private_messaging_sessions
          ),
          array_scope: array_scope,
          array_mapping_scope: ::Ai::Governance::Session.method(:in_optimization_array_mapping_scope),
          finder_query: ::Ai::Governance::Session.method(:in_optimization_finder_query)
        ).execute.preload_for_list
      end

      # Relation for the total count of {#execute}, as a plain `namespace_id IN (...)` filter.
      # Skips the private messaging check: SyncSessionArtifactWorker and the backfill never store those sessions,
      # and the check costs a workflow lookup per row. https://gitlab.com/gitlab-org/gitlab/-/work_items/633833
      # adds a column to filter on instead.
      #
      # @return [ActiveRecord::Relation<Ai::Governance::Session>]
      def count_relation
        return ::Ai::Governance::Session.none unless allowed?

        apply_filters(::Ai::Governance::Session.for_namespace(array_scope))
      end

      private

      attr_reader :current_user, :namespace, :params

      def allowed?
        Ability.allowed?(current_user, :read_agent_artifacts, namespace)
      end

      # `skope: ::Namespace` includes project namespaces, which hold project-scoped sessions.
      # An inclusion `project_path` narrows this to that project's namespace, so the lookup
      # runs once instead of once per namespace.
      def array_scope
        scope = namespace.self_and_descendants(skope: ::Namespace).select(:id)
        scope = scope.id_in(included_project.project_namespace_id) if included_project
        scope
      end

      def id_lookup
        apply_filters(::Ai::Governance::Session.for_namespace(array_scope).without_private_messaging_sessions)
          .order_by_session_started_at_and_id_desc
          .preload_for_list
      end

      def apply_filters(scope)
        scope = scope.id_in(params[:id]) if params[:id].present?
        scope = scope.for_agent_class(params[:agent_class])
        scope = filter_by_flow_type(scope)
        scope = filter_by_session_started_at(scope)
        scope = filter_by_user(scope)
        filter_by_project_path(scope)
      end

      def filter_by_flow_type(scope)
        scope = scope.for_flow_type(params[:flow_type]) if params[:flow_type].present?
        scope = scope.excluding_flow_type(not_param(:flow_type)) if not_param(:flow_type).present?
        scope
      end

      def filter_by_session_started_at(scope)
        if params[:session_started_after].present?
          scope = scope.for_session_started_after(params[:session_started_after])
        end

        if params[:session_started_before].present?
          scope = scope.for_session_started_before(params[:session_started_before])
        end

        scope
      end

      def filter_by_user(scope)
        scope = scope.for_user(params[:user_id]) if params[:user_id].present?
        scope = scope.excluding_user(not_param(:user_id)) if not_param(:user_id).present?
        scope
      end

      # An unresolvable inclusion path matches nothing; an unresolvable exclusion path excludes nothing.
      def filter_by_project_path(scope)
        if params[:project_path].present?
          return scope.none unless included_project

          scope = scope.for_project(included_project)
        end

        if not_param(:project_path).present?
          excluded_project = resolved_projects[not_param(:project_path)]
          scope = scope.excluding_project(excluded_project.id) if excluded_project
        end

        scope
      end

      def included_project
        resolved_projects[params[:project_path]] if params[:project_path].present?
      end
      strong_memoize_attr :included_project

      def resolved_projects
        paths = [params[:project_path], not_param(:project_path)].compact
        return {} if paths.empty?

        ::Project.where_full_path_in(paths).index_by(&:full_path)
      end
      strong_memoize_attr :resolved_projects

      def not_param(key)
        params.dig(:not, key)
      end
    end
  end
end
