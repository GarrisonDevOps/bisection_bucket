# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class McpServerTransportEnum < BaseEnum
        graphql_name 'AiCatalogMcpServerTransport'
        description 'Transport types for MCP servers'

        value 'HTTP', value: 'http', description: 'HTTP transport.'
      end
    end
  end
end
