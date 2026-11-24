# frozen_string_literal: true

module Mutations
  module Ai
    module Catalog
      module McpServer
        class Update < BaseMutation
          graphql_name 'AiCatalogMcpServerUpdate'

          field :mcp_server,
            ::Types::Ai::Catalog::McpServerType,
            null: true,
            description: 'MCP server that was updated.'

          argument :id, ::Types::GlobalIDType[::Ai::Catalog::McpServer],
            required: true,
            description: 'Global ID of the MCP server to update.'

          argument :name, GraphQL::Types::String,
            required: false,
            description: 'Name for the MCP server.'

          argument :description, GraphQL::Types::String,
            required: false,
            description: 'Description for the MCP server.'

          argument :url, GraphQL::Types::String,
            required: false,
            description: 'URL for the MCP server.'

          argument :homepage_url, GraphQL::Types::String,
            required: false,
            description: 'Homepage URL for the MCP server.'

          argument :transport, ::Types::Ai::Catalog::McpServerTransportEnum,
            required: false,
            description: 'Transport type for the MCP server.'

          argument :auth_type, ::Types::Ai::Catalog::McpServerAuthTypeEnum,
            required: false,
            description: 'Authentication type for the MCP server.'

          argument :oauth_client_id, GraphQL::Types::String,
            required: false,
            description: 'OAuth client ID for the MCP server.'

          argument :oauth_client_secret, GraphQL::Types::String,
            required: false,
            description: 'OAuth client secret for the MCP server.'

          authorize :update_ai_catalog_mcp_server
          authorize_granular_token permissions: :update_ai_catalog_mcp_server,
            boundary: :instance, boundary_type: :instance

          def resolve(id:, **args)
            mcp_server = authorized_find!(id: id)

            result = ::Ai::Catalog::McpServers::UpdateService.new(
              organization: mcp_server.organization,
              current_user: current_user,
              mcp_server: mcp_server,
              params: args
            ).execute

            {
              mcp_server: result.payload[:mcp_server],
              errors: result.errors
            }
          end
        end
      end
    end
  end
end
