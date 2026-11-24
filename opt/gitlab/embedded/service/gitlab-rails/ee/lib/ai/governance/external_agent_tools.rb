# frozen_string_literal: true

module Ai
  module Governance
    # The reviewed list of tool names connected agents record through the GitLab CLI,
    # by agent type and Registry privilege group. See external_agent_tools.yml for the
    # rule on adding a name.
    class ExternalAgentTools
      PATH = Rails.root.join('ee/lib/ai/governance/external_agent_tools.yml')

      class << self
        # { 'claude-code' => { 'read_only_files' => [{ 'name' => 'Read', ... }] } }
        def tools
          @tools ||= YAML.safe_load_file(PATH).freeze
        end

        # One flat row per listed tool: { agent_type:, group:, name:, docs:, seen_in: }.
        def rows
          @rows ||= tools.flat_map do |agent_type, groups|
            groups.flat_map do |group, entries|
              entries.map { |entry| { agent_type: agent_type, group: group.to_sym, **entry.symbolize_keys } }
            end
          end.freeze
        end

        # The Registry action type (:read, :write or :destroy) of a tool the agent
        # recorded, or nil when the pair is not on the list.
        def action_type_of(agent_type, tool_name)
          action_types[[agent_type, tool_name]]
        end

        private

        def action_types
          @action_types ||= rows.to_h do |row|
            [[row[:agent_type], row[:name]], action_type_for(row[:group])]
          end.freeze
        end

        def action_type_for(group)
          groups_by_type = ::Ai::ToolRules::Registry::ACTION_TYPE_GROUPS
          groups_by_type.each_key.find { |type| groups_by_type[type].include?(group) }
        end
      end
    end
  end
end
