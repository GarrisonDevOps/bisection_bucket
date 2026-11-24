# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class McpServerAuthTypeEnum < BaseEnum
        graphql_name 'AiCatalogMcpServerAuthType'
        description 'Authentication types for MCP servers'

        value 'OAUTH', value: 'oauth', description: 'OAuth authentication.'
        value 'NO_AUTH', value: 'no_auth', description: 'No authentication.'
      end
    end
  end
end
