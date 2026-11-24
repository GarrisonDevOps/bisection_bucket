# frozen_string_literal: true

module Resolvers
  module Ai
    module Catalog
      class McpServersResolver < BaseResolver
        description 'AI Catalog MCP servers.'

        type ::Types::Ai::Catalog::McpServerType.connection_type, null: false

        def resolve(**_args)
          return ::Ai::Catalog::McpServer.none unless Ability.allowed?(
            current_user, :read_ai_catalog_mcp_server, current_organization
          )

          ::Ai::Catalog::McpServer.in_organization(current_organization)
        end
      end
    end
  end
end
