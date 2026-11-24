# frozen_string_literal: true

module Ai
  module ToolRules
    class McpGovernance
      include ::Gitlab::Utils::StrongMemoize

      def self.enabled_anywhere?
        # rubocop:disable Gitlab/AvoidFeatureGet -- the actor is not known until containers are resolved; Flipper's cached state is the cheap way to skip that work
        Feature.enabled?(:duo_mcp_server_governance_rule_enforcement, :instance) ||
          !Feature.get(:duo_mcp_server_governance_rule_enforcement).off?
        # rubocop:enable Gitlab/AvoidFeatureGet
      end

      def self.governs?(container)
        Feature.enabled?(:duo_mcp_server_governance_rule_enforcement, container.root_ancestor)
      end

      def initialize(containers, include_projects: true, surface: ::Ai::ToolRules::GovernanceSurface::LOCAL)
        @containers = Array(containers).compact.uniq
        @include_projects = include_projects
        @surface = surface
      end

      def permission_for(tool_name)
        most_restrictive(verdicts_for(tool_name).map(&:first))
      end

      def explicit_permission_for(tool_name)
        verdicts = containers.flat_map do |container|
          verdicts_in(container) { |service| service.explicit_permission_for(tool_name) }
        end

        most_restrictive(verdicts.map(&:first))
      end

      def denied_by(tool_name)
        verdicts_for(tool_name).find { |permission, _| permission == Permissions::DENY }&.last
      end

      private

      attr_reader :containers, :include_projects, :surface

      def verdicts_for(tool_name)
        strong_memoize_with(:verdicts_for, tool_name) do
          containers.flat_map do |container|
            verdicts_in(container) { |service| service.permission_for(tool_name) }
          end
        end
      end

      def verdicts_in(container, &lookup)
        return [] unless self.class.governs?(container)
        return [[Permissions::DENY, container]] if ::Ai::ToolRules::GovernanceSurface.refused?(surface)

        own = [[yield(resolution_service_for(container)), container]]
        return own unless container.is_a?(::Group) && include_projects

        own + project_verdicts_under(container, &lookup)
      end

      def project_verdicts_under(group)
        ruled_projects_in(group).map do |project|
          [yield(resolution_service_for(project)), project]
        end
      end

      def ruled_projects_in(group)
        projects_with_rules(group.root_ancestor).select do |project|
          project.namespace.traversal_ids.include?(group.id)
        end
      end

      def projects_with_rules(root)
        strong_memoize_with(:projects_with_rules, root) do
          ::Ai::ToolRule.projects_for(rules_in(root))
        end
      end

      def resolution_service_for(container)
        namespace = container.root_ancestor
        project = container if container.is_a?(::Project)

        strong_memoize_with(:resolution_service_for, namespace, project) do
          ::Ai::ToolRules::ResolutionService.new(
            namespace: namespace,
            project: project,
            surface: surface_in(namespace),
            rules: rules_in(namespace)
          )
        end
      end

      def surface_in(root)
        return surface unless surface == ::Ai::ToolRules::GovernanceSurface::BACKGROUND
        return surface if Feature.enabled?(:duo_workflow_background_tool_governance, root)

        :ambient
      end

      def rules_in(root)
        strong_memoize_with(:rules_in, root) do
          if group_named_under?(root)
            ::Ai::ToolRule.within_namespace(root.id).to_a
          else
            ::Ai::ToolRule.for_namespace_and_projects(root.id, project_ids_under(root)).to_a
          end
        end
      end

      def group_named_under?(root)
        include_projects && containers.any? { |container| container.is_a?(::Group) && container.root_ancestor == root }
      end

      def project_ids_under(root)
        containers.select { |container| container.is_a?(::Project) && container.root_ancestor == root }.map(&:id)
      end

      def most_restrictive(verdicts)
        verdicts.compact.max_by { |permission| restrictiveness.fetch(permission.to_s, -1) }
      end

      def restrictiveness
        ::Ai::ToolRules::Permissions::RESTRICTIVENESS
      end
    end
  end
end
