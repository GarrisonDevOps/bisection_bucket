# frozen_string_literal: true

module Analytics
  module Orbit
    module TargetResolver
      def resolve_graph_status_context(params)
        target = find_graph_status_target(params)
        return unless target

        build_graph_status_context(target)
      end

      def build_graph_status_context(target)
        namespace = case target
                    when Group then target
                    when Project then target.project_namespace if target.namespace.is_a?(Group)
                    end
        return unless namespace

        { target: target, namespace: namespace, traversal_path: namespace.traversal_path(with_organization: true) }
      end

      private

      def find_graph_status_target(params)
        namespace_id = params[:namespace_id]
        project_id = params[:project_id]
        full_path = params[:full_path]

        if namespace_id
          Group.find_by_id(namespace_id)
        elsif project_id
          Project.find_by_id(project_id)
        elsif full_path
          Routable.find_by_full_path(full_path)
        end
      end
    end
  end
end
