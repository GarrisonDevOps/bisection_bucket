# frozen_string_literal: true

module Mutations
  module Ai
    module Catalog
      module McpServer
        class Create < BaseMutation
          graphql_name 'AiCatalogMcpServerCreate'

          field :mcp_server,
            ::Types::Ai::Catalog::McpServerType,
            null: true,
            description: 'MCP server created.'

          argument :name, GraphQL::Types::String,
            required: true,
            description: 'Name for the MCP server.'

          argument :description, GraphQL::Types::String,
            required: false,
            description: 'Description for the MCP server.'

          argument :url, GraphQL::Types::String,
            required: true,
            description: 'URL for the MCP server.'

          argument :homepage_url, GraphQL::Types::String,
            required: false,
            description: 'Homepage URL for the MCP server.'

          argument :transport, ::Types::Ai::Catalog::McpServerTransportEnum,
            required: true,
            description: 'Transport type for the MCP server.'

          argument :auth_type, ::Types::Ai::Catalog::McpServerAuthTypeEnum,
            required: true,
            description: 'Authentication type for the MCP server.'

          argument :oauth_client_id, GraphQL::Types::String,
            required: false,
            description: 'OAuth client ID for the MCP server.'

          argument :oauth_client_secret, GraphQL::Types::String,
            required: false,
            description: 'OAuth client secret for the MCP server.'

          authorize_granular_token permissions: :create_ai_catalog_mcp_server,
            boundary: :instance, boundary_type: :instance

          def resolve(**args)
            result = ::Ai::Catalog::McpServers::CreateService.new(
              organization: context[:current_organization],
              current_user: current_user,
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
