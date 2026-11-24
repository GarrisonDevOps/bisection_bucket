# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class McpConfigService
      include Gitlab::Utils::StrongMemoize

      ORBIT_PREAPPROVED_TOOLS = ::API::Orbit::McpHandlers::ToolCatalog::COMMAND_TOOL_NAMES

      # Workhorse advertises each MCP tool as `<server>_<tool>`, so the claim has to say
      # `gitlab_search`, not `search`. See workhorse/internal/ai_assist/duoworkflow/mcp.go.
      MCP_SERVER_TOOL_PREFIX = 'gitlab_'

      # Workflow definitions for agentic chat, which should receive MCP tools.
      # `agentic_chat/v1` is the flow-registry successor to the legacy `chat`
      # definition and must be recognized here too, otherwise resumed sessions
      # (which send the stored `agentic_chat/v1` definition) get zero MCP tools.
      # See: https://gitlab.com/groups/gitlab-org/-/work_items/19647
      # Foundational agents (e.g., "software_development", "analytics_agent/v1")
      # have their own toolsets and should not receive injected MCP tools.
      # See: https://gitlab.com/gitlab-org/gitlab/-/issues/583935
      AGENTIC_CHAT_DEFINITIONS = %w[chat agentic_chat/v1].freeze

      def initialize(
        current_user, gitlab_token, workflow_definition: nil,
        ai_catalog_item_version_id: nil, namespace: nil, workflow: nil)
        @current_user = current_user
        @gitlab_token = gitlab_token
        @workflow_definition = workflow_definition
        @ai_catalog_item_version_id = ai_catalog_item_version_id
        @namespace = namespace
        @workflow = workflow
      end

      # This method returns configuration for supported MCP servers
      #
      # Expected configuration format is:
      #
      # {
      #   server_name: {
      #     URL: <server-url>,
      #     Headers: <headers-send-on-each-request>,
      #     Tools: <list-of-supported-tools>, # omitted/nil means all tools will be listed
      #     PreApprovedTools: <list-of-preapproved-tools> # tools that don't require user approval
      #   }
      # }
      #
      # GitLab configuration is hard-coded, while the list may also contain other server configurations
      # For example,
      # {
      #   gitlab: gitlab_mcp_server,
      #   context7: {
      #     URL: "https://mcp.context7.com/mcp",
      #   }
      # }
      #
      # Or the list can be extended by user provided configurations on namespace/project/user levels
      def execute(denied: [])
        return orbit_mcp_server unless mcp_client_enabled?

        gitlab_mcp_server(denied)
          .merge(orbit_mcp_server)
          .merge(ai_catalog_mcp_servers.except(:orbit))
          .merge(slack_mcp_server)
      end

      # Duo Chat drops its native search tools whenever this header names `search`, so leaving a
      # denied `search` in it removes them with nothing in their place.
      def gitlab_enabled_tools(denied:)
        return [] unless mcp_client_enabled?
        return [] unless gitlab_mcp_enabled?

        agent_tools_or_default(preapproved_tools_from_annotations) - withheld_server_tools(denied)
      end

      def preapproved_tool_names
        return orbit_claim_preapproved_tools unless mcp_client_enabled?

        orbit_claim_preapproved_tools + gitlab_claim_preapproved_tools + slack_claim_preapproved_tools
      end

      private

      attr_reader :gitlab_token, :current_user, :workflow_definition, :ai_catalog_item_version_id, :namespace,
        :workflow

      def mcp_client_enabled?
        Feature.enabled?(:mcp_client, current_user)
      end
      strong_memoize_attr :mcp_client_enabled?

      # The deny claim spells MCP tools `gitlab_search` while the header and config spell them
      # `search` plus any declared aliases, so a denied tool is matched in both forms.
      def withheld_server_tools(denied)
        canonical = denied.filter_map do |name|
          name.delete_prefix(MCP_SERVER_TOOL_PREFIX) if name.start_with?(MCP_SERVER_TOOL_PREFIX)
        end & all_mcp_tools

        canonical + canonical.flat_map { |name| mcp_tools_manager.aliases_for(name) }
      end

      # Emitted into the `tool_access_policies` claim's allow list, `gitlab_`
      # prefixed. The Duo Workflow Service treats that list as the pre-approval
      # ceiling, so anything Workhorse pre-approves has to be repeated here or
      # it prompts for approval anyway. Aliases are dropped: the MCP server
      # serves canonical names only, so a prefixed alias would match nothing.
      def gitlab_claim_preapproved_tools
        return [] unless gitlab_mcp_enabled?

        (preapproved_tools - tool_alias_names).map do |tool_name|
          "#{MCP_SERVER_TOOL_PREFIX}#{tool_name}"
        end
      end

      # The flow pre-approves these whether or not this session gets the server: pre-approving a tool the
      # session doesn't have does nothing, and the claim then needs no call to Slack.
      def slack_claim_preapproved_tools
        return [] unless session_gets_slack_server?

        ::Ai::Catalog::McpServers::SlackHelper::PRE_APPROVED_TOOLS
      end

      def orbit_claim_preapproved_tools
        return [] unless orbit_mcp_client_enabled?

        orbit_tools_to_inject.map { |tool_name| "orbit_#{tool_name}" }
      end

      def agentic_chat?
        AGENTIC_CHAT_DEFINITIONS.include?(workflow_definition)
      end

      def agent_has_tools?
        built_in_tool_ids.present? || agent_mcp_tools_enabled?
      end

      def agent_mcp_tools_enabled?
        agent_mcp_tools.present?
      end

      def item_version
        return unless ai_catalog_item_version_id.present?

        ::Ai::Catalog::ItemVersion.find_by_id(ai_catalog_item_version_id)
      end
      strong_memoize_attr :item_version

      def built_in_tool_ids
        @built_in_tool_ids ||= item_version ? Array(item_version.def_tools) : []
      end

      def agent_mcp_tools
        @agent_mcp_tools ||= Array((item_version || foundational_agent_item_version)&.def_mcp_tools)
      end

      # Foundational agents start without an ai_catalog_item_version_id, so the MCP tools selected on them were
      # dropped and only Orbit tools reached the agent. Resolve the agent's catalog version here so its selected
      # MCP tools are honored without flipping custom_agent?, which would change Orbit gating.
      def foundational_agent_item_version
        return if ai_catalog_item_version_id.present?

        agent = ::Ai::FoundationalChatAgent.with_workflow_definition(workflow_definition)
        return unless agent&.global_catalog_id

        ::Ai::Catalog::Item.find_by_id(agent.global_catalog_id)&.latest_released_version_with_fallback
      end
      strong_memoize_attr :foundational_agent_item_version

      def gitlab_mcp_enabled?
        agentic_chat? || agent_has_tools?
      end

      # Deliberately per request, not per process: the tool list comes from
      # `API::API.routes`, so caching it across requests risks pinning a list
      # built before Grape finished compiling.
      def mcp_tools_manager
        ::Mcp::Tools::Manager.new
      end
      strong_memoize_attr :mcp_tools_manager

      def all_mcp_tools
        mcp_tools_manager.list_tools.keys
      end

      def tool_alias_names
        mcp_tools_manager.alias_map.keys
      end
      strong_memoize_attr :tool_alias_names

      # Derives the pre-approved GitLab MCP tools from each tool's own `readOnlyHint`
      # annotation instead of a hand-maintained list, so a read-only tool is
      # automatically pre-approved (and its aliases follow the tool's status).
      def preapproved_tools_from_annotations
        read_only = mcp_tools_manager.list_tools.select do |_tool_name, tool|
          tool.annotations.fetch(:readOnlyHint, false)
        end.keys

        aliases = mcp_tools_manager.alias_map.select { |_name, canonical| read_only.include?(canonical) }.keys

        read_only + aliases
      end
      strong_memoize_attr :preapproved_tools_from_annotations

      def preapproved_tools
        if agent_has_tools?
          mcp_tools_for_agent & preapproved_tools_from_annotations
        else
          preapproved_tools_from_annotations
        end
      end
      strong_memoize_attr :preapproved_tools

      def gitlab_mcp_server(denied)
        return {} unless gitlab_mcp_enabled?

        withheld = withheld_server_tools(denied)

        config = {
          Headers: {
            Authorization: "Bearer #{gitlab_token}"
          },
          PreApprovedTools: preapproved_tools - withheld,
          Trusted: true
        }

        if agent_has_tools?
          config[:Tools] = mcp_tools_for_agent - withheld
          # tools/list leaves out unlisted and opt-in toolset tools unless the request names them.
          config[:Headers][:'X-Gitlab-Enabled-Mcp-Server-Tools'] = (config[:Tools] & all_mcp_tools).join(',')
        elsif withheld.any?
          config[:Tools] = all_mcp_tools - withheld
        end

        { gitlab: config }
      end

      def orbit_mcp_server
        return {} unless orbit_mcp_client_enabled?

        tools = orbit_tools_to_inject

        config = {
          Headers: {
            Authorization: "Bearer #{gitlab_token}"
          },
          PreApprovedTools: tools,
          Trusted: true
        }

        config[:Tools] = tools if custom_agent?

        { orbit: config }
      end

      def orbit_mcp_client_enabled?
        # Don't inject orbit tools when running a custom agent that
        # has not selected any orbit tools. Custom agents that want
        # orbit access must explicitly select orbit tools.
        return false if custom_agent? && agent_orbit_tools.none?

        # All gating (platform availability, per-user preference flag,
        # killswitch, and granular subsettings) lives behind the
        # ::Ai::Orbit::Settings facade so this service does not have to
        # know about individual feature flags or preference shapes.
        orbit_enabled_for_flow?
      end

      def orbit_enabled_for_flow?
        if code_review?
          # Duo Code Review is flat-rate; exclude from the foundational catch-all
          # until the flow integrates Orbit deliberately and is benchmarked.
          false
        elsif custom_agent?
          ::Ai::Orbit::Settings.custom_agents_enabled?(current_user)
        elsif orbit_agent?
          ::Ai::Orbit::Settings.agent_enabled?(current_user)
        elsif agentic_chat?
          ::Ai::Orbit::Settings.chat_enabled?(current_user)
        else
          # Catch-all for non-chat foundational agents (e.g. 'software_development',
          # 'security_analyst_agent/v1'). Also covers nil and unrecognized
          # workflow definitions; add a new subsetting and explicit branch
          # above if we ever need to gate those separately.
          ::Ai::Orbit::Settings.foundational_enabled?(current_user)
        end
      end

      def code_review?
        workflow_definition&.start_with?('code_review/')
      end

      def custom_agent?
        ai_catalog_item_version_id.present? && agent_has_tools?
      end

      # Returns the orbit tools to include in the MCP config.
      # For custom agents, only the explicitly selected orbit tools;
      # for plain agentic chat / dedicated orbit agent, all orbit tools.
      def orbit_tools_to_inject
        custom_agent? ? agent_orbit_tools : ORBIT_PREAPPROVED_TOOLS
      end

      def agent_orbit_tools
        Array(agent_mcp_tools) & ORBIT_PREAPPROVED_TOOLS
      end
      strong_memoize_attr :agent_orbit_tools

      def orbit_agent?
        workflow_definition&.start_with?('orbit_agent')
      end

      # Built-in and MCP tool names are intersected with the MCP server's available
      # tools so the agent only receives tools the server can actually execute. If
      # the agent has no MCP tools configured, built-in tools are returned as-is;
      # otherwise the `& available` intersection would filter out any built-in tool
      # whose name doesn't happen to match an MCP tool, silently breaking agents
      # with no MCP tools.
      def mcp_tools_for_agent
        built_in_names = Ai::Catalog::BuiltInTool.where(id: built_in_tool_ids).map(&:name) # rubocop:disable CodeReuse/ActiveRecord -- BuiltInTool is a FixedItemsModel, not a real ActiveRecord model

        if agent_mcp_tools_enabled?
          available = all_mcp_tools
          ((built_in_names + resolve_agent_mcp_tools) & available).uniq
        else
          built_in_names
        end
      end
      strong_memoize_attr :mcp_tools_for_agent

      # MCP aliases are resolved only for agent_mcp_tools, not built_in_names.
      # Built-in tools come from a different registry and MCP aliases should not rewrite them.
      def resolve_agent_mcp_tools
        Array(agent_mcp_tools).map { |name| mcp_tools_manager.resolve_alias(name) }
      end

      def agent_tools_or_default(default)
        agent_has_tools? ? mcp_tools_for_agent : default
      end

      def ai_catalog_mcp_servers
        return {} unless ai_catalog_item_version_id

        item_version = ::Ai::Catalog::ItemVersion.find_by_id(ai_catalog_item_version_id)
        return {} unless Ability.allowed?(current_user, :read_ai_catalog_item, item_version)

        ::Ai::Catalog::McpServers::ConfigService.new(item_version, current_user, namespace: namespace).execute
      end

      def slack_mcp_server
        return {} unless session_gets_slack_server?

        ::Ai::Catalog::McpServers::SlackConfigService
          .new(current_user, namespace: namespace, workflow: workflow).execute
      end
      strong_memoize_attr :slack_mcp_server

      def session_gets_slack_server?
        ::Ai::Catalog::McpServers::SlackHelper.session_gets_slack_server?(current_user, workflow_definition)
      end
    end
  end
end
