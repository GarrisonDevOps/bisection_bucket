# frozen_string_literal: true

module Ai
  module Catalog
    module McpServers
      class ListService
        def initialize(agent_version, current_user, namespace: nil)
          @agent_version = agent_version
          @current_user = current_user
          @namespace = namespace
        end

        def execute
          return ::Ai::Catalog::McpServer.none unless allowed?

          server_ids = Array(agent_version.def_mcp_servers).uniq
          without_blocked_servers(::Ai::Catalog::McpServer.id_in(server_ids), server_ids)
        end

        private

        attr_reader :agent_version, :current_user, :namespace

        def allowed?
          Ability.allowed?(current_user, :read_ai_catalog_mcp_server, agent_version.organization)
        end

        def without_blocked_servers(servers, server_ids)
          return servers if server_ids.blank?
          return servers unless namespace
          return servers unless Feature.enabled?(:mcp_server_block_enforcement, namespace.root_ancestor)

          servers.id_not_in(::Ai::Catalog::McpServerBlock.blocked_server_ids_for(namespace, server_ids))
        end
      end
    end
  end
end
