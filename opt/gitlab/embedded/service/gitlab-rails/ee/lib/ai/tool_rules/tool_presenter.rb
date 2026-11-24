# frozen_string_literal: true

module Ai
  module ToolRules
    module ToolPresenter
      ACRONYMS = %w[CI ASCP GitLab GLQL SAST FP MCP GraphQL MR].freeze

      DISPLAY_NAME_OVERRIDES = {
        'gitlab__user_search' => 'GitLab User Search',
        'mcp__duo__review' => 'Duo CLI Code Review',
        'post_sast_fp_analysis_to_gitlab' => 'Post SAST False Positive Analysis to GitLab',
        'post_secret_fp_analysis_to_gitlab' => 'Post Secret False Positive Analysis to GitLab'
      }.freeze

      # Each access type resolves on its own, so a project rule that is stricter on one
      # surface does not hide the namespace value of another.
      #
      # @param tool_name [String]
      # @param namespace_rule [Ai::ToolRule, nil]
      # @param project_rule [Ai::ToolRule, nil]
      # @param project_scoped [Boolean] whether configured_access shows the project rule
      # @param mcp_tools [Ai::ToolRules::GovernedMcpTools, nil]
      # @param first_party_tools [Ai::ToolRules::FirstPartyTools, nil]
      # @param fail_closed [Boolean] see {Ai::ToolRules::GovernanceSurface.background_fail_closed?}
      # @return [Hash] the tool's settings-page row
      def self.tool_rule_for(
        tool_name, namespace_rule:, project_rule:, project_scoped:, mcp_tools: nil, first_party_tools: nil,
        fail_closed: false
      )
        scope_rule = project_scoped ? project_rule : namespace_rule
        catalogs = { mcp_tools: mcp_tools, first_party_tools: first_party_tools }
        default_access = default_access_for(tool_name, **catalogs, fail_closed: fail_closed)

        {
          id: tool_name,
          name: display_name_for(tool_name),
          action_type: Registry.action_type_of(tool_name, **catalogs),
          category: Registry.category_for(tool_name, **catalogs),
          source: Registry.source_for(tool_name, **catalogs),
          configured_access: Permissions::ACCESS_TYPES.index_with { |type| scope_rule && scope_rule[type] },
          default_access: default_access
        }.merge(
          Permissions::ACCESS_TYPES.index_with do |access_type|
            rules = [namespace_rule, project_rule]
            # The fail-closed default binds a project rule like a group rule does.
            fail_closed_floor = fail_closed && access_type == :background_access && namespace_rule&.[](access_type).nil?
            rules << default_access if fail_closed_floor

            most_restrictive(rules, access_type) || default_access[access_type]
          end
        )
      end

      # @param tool_name [String]
      # @param mcp_tools [Ai::ToolRules::GovernedMcpTools, nil]
      # @param first_party_tools [Ai::ToolRules::FirstPartyTools, nil]
      # @param fail_closed [Boolean] see {Ai::ToolRules::GovernanceSurface.background_fail_closed?}
      # @return [Hash{Symbol => String}] the default permission per access type
      def self.default_access_for(tool_name, mcp_tools: nil, first_party_tools: nil, fail_closed: false)
        default = Registry.default_permission_of(tool_name, mcp_tools: mcp_tools, first_party_tools: first_party_tools)

        {
          web_access: default,
          local_access: default,
          background_access: Permissions.background_effective(default, fail_closed: fail_closed)
        }
      end

      def self.most_restrictive(rules, access_type)
        rules.filter_map { |rule| rule[access_type] if rule }
          .max_by { |permission| Permissions::RESTRICTIVENESS[permission] }
      end
      private_class_method :most_restrictive

      def self.display_name_for(tool_name)
        DISPLAY_NAME_OVERRIDES.fetch(tool_name) do
          tool_name.split('_').map do |word|
            ACRONYMS.find { |a| a.downcase == word } || word.capitalize
          end.join(' ')
        end
      end
    end
  end
end
