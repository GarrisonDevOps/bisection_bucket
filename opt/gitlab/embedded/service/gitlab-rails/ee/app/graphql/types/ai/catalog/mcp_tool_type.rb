# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      # rubocop: disable Graphql/AuthorizeTypes -- Always public
      class McpToolType < ::Types::BaseObject
        graphql_name 'AiCatalogMcpTool'
        description 'An MCP tool dynamically discovered from the GitLab MCP server.'
        authorize_granular_token permissions: :read_ai_catalog_item, boundary: :user, boundary_type: :user

        field :beta, GraphQL::Types::Boolean, null: false,
          description: 'Whether the MCP tool is in beta. The AI Catalog shows a Beta badge for beta tools.'
        field :description, String, null: true, description: 'Description of the MCP tool.'
        field :icons, [Types::Ai::Catalog::McpToolIconType], null: false,
          description: 'Icons advertised for the MCP tool, per the MCP spec icons field.'
        field :name, GraphQL::Types::ID, null: false, description: 'Machine-readable name of the MCP tool.'
        field :title, String, null: false, description: 'Human-readable title of the MCP tool.'

        def icons
          ::Mcp::Tools::Base::IconConfig.gitlab_icons
        end
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
