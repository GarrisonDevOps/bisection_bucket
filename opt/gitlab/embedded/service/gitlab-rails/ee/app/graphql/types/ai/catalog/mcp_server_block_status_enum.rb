# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class McpServerBlockStatusEnum < BaseEnum
        graphql_name 'AiCatalogMcpServerBlockStatus'
        description 'Block status of an MCP server for a group or project'

        value 'ACTIVE', value: 'active', description: 'Server is allowed for the group or project.'
        value 'BLOCKED', value: 'blocked', description: 'Server is blocked directly on the group or project.'
        value 'BLOCKED_BY_ANCESTOR', value: 'blocked_by_ancestor',
          description: 'Server is blocked by an ancestor group and cannot be allowed here.'
      end
    end
  end
end
