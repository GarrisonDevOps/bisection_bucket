# frozen_string_literal: true

module Resolvers
  module Ai
    module Catalog
      class McpServerResolver < BaseResolver
        description 'Find an AI Catalog MCP server by ID.'

        type ::Types::Ai::Catalog::McpServerType, null: true

        argument :id, ::Types::GlobalIDType[::Ai::Catalog::McpServer],
          required: true,
          description: 'Global ID of the MCP server.'

        def resolve(id:)
          GitlabSchema.find_by_gid(id)
        end
      end
    end
  end
end
