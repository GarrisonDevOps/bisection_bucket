# frozen_string_literal: true

module EE
  module Mcp
    module Tools
      module Manager
        extend ::Gitlab::Utils::Override

        # Registry of all EE custom tools mapped to their service classes.
        EE_CUSTOM_TOOLS = {}.freeze
        EE_GRAPHQL_TOOLS = {
          'attach_scan_profile' => ::Mcp::Tools::Security::AttachScanProfileService,
          'get_duo_session' => ::Mcp::Tools::DuoWorkflows::GetDuoSessionService,
          'get_vulnerability' => ::Mcp::Tools::Security::GetVulnerabilityService,
          'list_duo_agents_and_flows' => ::Mcp::Tools::DuoWorkflows::ListDuoAgentsAndFlowsService,
          'list_duo_sessions' => ::Mcp::Tools::DuoWorkflows::ListDuoSessionsService,
          'list_vulnerabilities' => ::Mcp::Tools::Security::ListVulnerabilitiesService,
          'save_vulnerability' => ::Mcp::Tools::Security::SaveVulnerabilityService
        }.freeze

        private

        override :user_tools
        def user_tools(context, toolsets)
          return super unless context && toolsets.include?(:orbit)

          ::Mcp::Tools::Orbit::CommandCatalog.tools_for(context)
        end

        override :custom_tools
        def custom_tools
          @custom_tools ||= super.merge(EE_CUSTOM_TOOLS).freeze
        end

        override :graphql_tools
        def graphql_tools
          @graphql_tools ||= super.merge(EE_GRAPHQL_TOOLS).freeze
        end
      end
    end
  end
end
