# frozen_string_literal: true

module Resolvers
  module Ai
    class ToolRulesResolver < BaseResolver
      include LooksAhead

      authorize :read_ai_tool_rule
      authorize_granular_token permissions: :read_ai_tool_rule, boundary_argument: :full_path, boundary_type: :group

      type Types::Ai::ToolRuleType.connection_type, null: true

      argument :full_path, GraphQL::Types::ID,
        required: true,
        description: 'Full path of the root namespace to fetch tool rules for.'

      argument :project_path, GraphQL::Types::ID,
        required: false,
        description: 'Full path of the project to fetch effective tool rules for. ' \
          'When provided, returns the merged effective rules for the project, ' \
          'applying most-restrictive-wins across namespace and project rules.'

      argument :search, GraphQL::Types::String,
        required: false,
        description: 'Case-insensitive text search on tool name or display name.'

      argument :action_type, Types::Ai::ToolActionTypeEnum,
        required: false,
        description: 'Filter tools by action type.'

      argument :source, Types::Ai::ToolSourceEnum,
        required: false,
        experiment: { milestone: '19.7' },
        description: 'Filter tools by source.'

      def resolve_with_lookahead(full_path:, project_path: nil, search: nil, action_type: nil, source: nil)
        namespace = authorized_find!(full_path: full_path)
        project = project_path ? ::Project.find_by_full_path(project_path) : nil

        raise_resource_not_available_error! if project && !Ability.allowed?(current_user, :read_project, project)

        if project && project.root_namespace.id != namespace.id
          raise_resource_not_available_error! "Project does not belong to the namespace"
        end

        namespace_rules = ::Ai::ToolRule.for_namespace(namespace.id).index_by(&:tool_name)
        project_rules = project ? ::Ai::ToolRule.for_project(project.id).index_by(&:tool_name) : {}

        search_term = search&.downcase
        normalized_action_type = action_type&.to_sym

        catalogs = {
          mcp_tools: ::Ai::ToolRules::GovernedMcpTools.for(namespace),
          first_party_tools: ::Ai::ToolRules::FirstPartyTools.for(namespace)
        }
        fail_closed = ::Ai::ToolRules::GovernanceSurface.background_fail_closed?(namespace)

        ::Ai::ToolRules::Registry.rulable_tool_names(**catalogs).filter_map do |tool_name|
          next unless matches_filters?(tool_name, search_term, normalized_action_type, source, catalogs)

          ::Ai::ToolRules::ToolPresenter.tool_rule_for(
            tool_name,
            namespace_rule: namespace_rules[tool_name],
            project_rule: project_rules[tool_name],
            project_scoped: project.present?,
            **catalogs,
            fail_closed: fail_closed
          )
        end
      end

      private

      def find_object(full_path:, **_kwargs)
        namespace = ::Namespace.find_by_full_path(full_path)
        namespace&.root? ? namespace : nil
      end

      def matches_filters?(tool_name, search_term, normalized_action_type, source, catalogs)
        tool_action_type = ::Ai::ToolRules::Registry.action_type_of(tool_name, **catalogs)
        return false if normalized_action_type && tool_action_type != normalized_action_type
        return false if source && ::Ai::ToolRules::Registry.source_for(tool_name, **catalogs) != source
        return true if search_term.blank? || tool_name.include?(search_term)

        ::Ai::ToolRules::ToolPresenter.display_name_for(tool_name).downcase.include?(search_term)
      end
    end
  end
end
