# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      # rubocop: disable Graphql/AuthorizeTypes -- Always public
      class McpToolIconType < ::Types::BaseObject
        graphql_name 'AiCatalogMcpToolIcon'
        description 'An icon advertised for an MCP tool, per the MCP spec icons field.'
        authorize_granular_token parent_authorizes: :read_ai_catalog_item

        field :mime_type, String, null: false, description: 'MIME type of the icon image.',
          hash_key: :mimeType
        field :src, String, null: false, description: 'URL to the icon image.'
        field :theme, String, null: true,
          description: 'Theme the icon is intended for: "light" or "dark".'
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
