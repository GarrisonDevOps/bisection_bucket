# frozen_string_literal: true

module Ai
  module ToolRules
    # Governance metadata for the tools GitLab's own MCP server serves.
    #
    # Action types come from the annotations each tool already declares, so a newly
    # served tool is governed without a change here.
    #
    # Discovery must stay lazy: Grape memoizes `API::API.routes` after boot, so a manager
    # built at class-definition time would see an incomplete route list.
    class GovernedMcpTools
      REQUEST_STORE_KEY = :ai_tool_rules_governed_mcp_tools

      class << self
        def for(namespace)
          return none unless namespace
          return none unless Feature.enabled?(:duo_mcp_tool_governance, namespace)

          # Cached under a namespace-independent key on purpose: the served set is
          # instance-wide, and the flag is checked above, so a namespace with the flag
          # off returns `none` without ever reading this entry.
          Gitlab::SafeRequestStore.fetch(REQUEST_STORE_KEY) { new(build_entries) }
        end

        def none
          @none ||= new({})
        end

        private

        def build_entries
          manager = ::Mcp::Tools::Manager.new

          manager.list_tools.each_with_object({}) do |(name, tool), entries|
            tool_name = name.to_s

            # Unlisted tools stay governed: they are hidden from tools/list but remain
            # callable, so a deny rule must keep reaching them.
            next if Registry::UNGOVERNED_TOOLS.include?(tool_name)

            identities = catalog_identities_for(tool_name, manager)

            entries[tool_name] = {
              identities: identities,
              mcp_identities: (identities + identities.flat_map { |name| retirement_identities_for(name) }).uniq,
              action_type: action_type_for_tool(tool)
            }
          end
        end

        # A tool declaring no catalog alias stands as its own identity, which keeps a tool
        # served under a catalog name reachable by the rule on that name. `all_tool_names`
        # rather than the mapping, because a mapped but uncataloged name can carry no rule.
        def catalog_identities_for(tool_name, manager)
          twins = manager.aliases_for(tool_name).select { |name| Registry.all_tool_names.include?(name) }

          twins.presence || [tool_name]
        end

        def retirement_identities_for(catalog_name)
          map = Registry::REPLACEMENT_TOOL_FOR
          linked = [map[catalog_name], *map.select { |_, to| to == catalog_name }.keys]

          linked.compact.select { |name| Registry.all_tool_names.include?(name) }
        end

        def action_type_for_tool(tool)
          annotations = tool.annotations.to_h

          # `destructiveHint` is checked first so a tool declaring both hints resolves to
          # the restrictive one. Reading `readOnlyHint` first would classify a
          # self-declared destructive tool as Read, which defaults to allow.
          return :destroy if annotations[:destructiveHint] == true
          return :read if annotations[:readOnlyHint] == true
          return :write if annotations.key?(:readOnlyHint)

          # Assume the most restrictive class if nothing is declared.
          :destroy
        end
      end

      def initialize(entries)
        @entries = entries.freeze
      end

      def empty?
        @entries.empty?
      end

      # Every MCP tool governance knows about. `rulable_names` narrows this to the ones
      # carrying a rule under their own name, which is the wrong question for a guardrail:
      # a tool governed under a catalog twin still has to resolve a namespace.
      def names
        @entries.keys
      end

      # MCP tool names that carry a rule of their own. A served name with a catalog twin
      # is governed by that catalog name instead.
      def rulable_names
        @rulable_names ||= @entries.filter_map do |tool_name, entry|
          next if Registry.all_tool_names.include?(tool_name)
          next if entry[:identities] != [tool_name]

          tool_name
        end.freeze
      end

      def identities_for(tool_name)
        @entries.dig(tool_name, :mcp_identities) || []
      end

      def action_type_for(tool_name)
        @entries.dig(tool_name, :action_type)
      end

      # Prefixed spellings the Duo Workflow Service addresses `governed_name` by. Without
      # these a rule stored under a bare name never reaches the MCP transport.
      def spellings_for(governed_name)
        spellings_by_identity.fetch(governed_name, [])
      end

      # The rule a recorded spelling is governed by, prefixed or bare. Nil when it names no
      # served tool, or a tool with several catalog aliases, which no single rule governs.
      def rule_for_spelling(spelling)
        rules = rules_by_spelling[spelling]
        rules.first if rules&.one?
      end

      private

      def rules_by_spelling
        @rules_by_spelling ||= begin
          map = spellings_by_identity.each_with_object({}) do |(identity, spellings), result|
            spellings.each { |spelling| (result[spelling] ||= []) << identity }
          end

          # A catalog name stays with its own rule, so a bare spelling never overrides it.
          @entries.each do |tool_name, entry|
            (map[tool_name] ||= []).concat(entry[:identities]) unless Registry.all_tool_names.include?(tool_name)
          end

          map.freeze
        end
      end

      def spellings_by_identity
        @spellings_by_identity ||= begin
          prefix = ::Ai::DuoWorkflows::McpConfigService::MCP_SERVER_TOOL_PREFIX

          @entries.each_with_object({}) do |(tool_name, entry), map|
            entry[:identities].each { |identity| (map[identity] ||= []) << "#{prefix}#{tool_name}" }
          end.freeze
        end
      end
    end
  end
end
