# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module SessionArtifacts
      class PostgresqlFinder
        include ::Gitlab::Utils::StrongMemoize

        def initialize(namespace:, params: {})
          @namespace = namespace
          @params = params
        end

        def execute
          # Scopes to the namespace hierarchy via a single `namespace_id IN (...)`
          # lookup, optimized with the in-operator technique so keyset/offset
          # pagination reads close to one page worth of rows instead of
          # materializing the whole hierarchy.
          # See https://docs.gitlab.com/development/database/efficient_in_operator_queries
          # `with_project` is applied to the result, not the input scope: the
          # in-operator builder returns a fresh `SELECT * FROM (cte)` relation, so
          # a preload set on the input scope would be dropped.
          artifact_scope = ::Ai::DuoWorkflows::SessionArtifact
          artifact_scope = apply_filters(artifact_scope)

          ::Gitlab::Pagination::Keyset::InOperatorOptimization::QueryBuilder.new(
            scope: artifact_scope.with_keyset_order,
            array_scope: array_scope,
            array_mapping_scope: ::Ai::DuoWorkflows::SessionArtifact.method(:in_optimization_array_mapping_scope),
            finder_query: ::Ai::DuoWorkflows::SessionArtifact.method(:in_optimization_finder_query)
          ).execute.with_project.with_user
        end

        private

        attr_reader :namespace, :params

        # All namespace ids in the hierarchy. `skope: ::Namespace` is required so
        # the result includes project namespaces (whose `traversal_ids` contain
        # the group id); the default `skope` would restrict to `Group` and miss
        # every project-scoped artifact.
        #
        # Every row for a project carries that project's `project_namespace_id`, so an
        # inclusion `project_path` narrows this to one namespace and the builder's LATERAL
        # join runs once instead of once per namespace. Chained, not replaced, so it stays
        # an intersection and a project outside the hierarchy still matches nothing.
        def array_scope
          scope = namespace.self_and_descendants(skope: ::Namespace).select(:id)
          scope = scope.id_in(included_project.project_namespace_id) if included_project
          scope
        end

        def apply_filters(scope)
          scope = scope.for_workflow(params[:workflow_id]) if params[:workflow_id].present?
          scope = filter_by_agent_type(scope)
          scope = filter_by_workflow_definition(scope)
          scope = filter_by_created_at(scope)
          scope = filter_by_user(scope)
          filter_by_project_path(scope)
        end

        def filter_by_agent_type(scope)
          case params[:agent_type_filter]
          when :any then scope.with_any_agent_type
          when :none then scope.with_no_agent_type
          else scope
          end
        end

        def filter_by_workflow_definition(scope)
          scope = scope.for_workflow_definition(params[:workflow_definition]) if params[:workflow_definition].present?

          if not_param(:workflow_definition).present?
            scope = scope.excluding_workflow_definition(not_param(:workflow_definition))
          end

          scope
        end

        # Date bounds are inclusive (>= / <=) to match the ClickHouse finder.
        def filter_by_created_at(scope)
          if params[:workflow_created_after].present?
            scope = scope.for_workflow_created_after(params[:workflow_created_after])
          end

          if params[:workflow_created_before].present?
            scope = scope.for_workflow_created_before(params[:workflow_created_before])
          end

          scope
        end

        def filter_by_user(scope)
          scope = scope.for_user(params[:user_id]) if params[:user_id].present?
          scope = scope.excluding_user(not_param(:user_id)) if not_param(:user_id).present?
          scope
        end

        # Returns an empty scope when the inclusion path does not resolve, and skips the
        # exclusion filter when the exclusion path does not resolve (nothing to exclude).
        # The inclusion predicate is redundant once `array_scope` is narrowed, but is kept
        # so this filter stays correct if that invariant is ever broken.
        #
        # The exclusion deliberately does not narrow `array_scope`: dropping the project
        # namespace would also drop the `project_id IS NULL` rows a namespace-level
        # workflow can put there, which is what `excluding_project` exists to preserve.
        def filter_by_project_path(scope)
          if params[:project_path].present?
            return scope.none unless included_project

            scope = scope.for_project(included_project.id)
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

        # Resolves both the inclusion and exclusion paths in one query, memoized so
        # `array_scope` and `apply_filters` share a single lookup.
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
end
