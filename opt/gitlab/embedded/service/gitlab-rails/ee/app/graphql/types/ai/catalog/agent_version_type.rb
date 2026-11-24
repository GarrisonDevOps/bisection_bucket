# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class AgentVersionType < ::Types::BaseObject
        graphql_name 'AiCatalogAgentVersion'
        description 'An AI catalog agent version'
        authorize :read_ai_catalog_item
        authorize_granular_token permissions: :read_ai_catalog_item, boundary: :user, boundary_type: :user

        implements ::Types::Ai::Catalog::VersionInterface

        field :mcp_servers, ::Types::Ai::Catalog::McpServerType.connection_type,
          null: true,
          description: 'MCP servers associated with the item.',
          experiment: { milestone: '18.10' }
        # rubocop:disable GraphQL/ExtractType -- mcp_tools belongs on this type as a flat field alongside mcp_servers
        field :mcp_tools, [GraphQL::Types::String], null: true,
          method: :def_mcp_tools,
          description: 'List of MCP tools enabled for the agent.',
          experiment: { milestone: '18.11' }
        # rubocop:enable GraphQL/ExtractType
        field :system_prompt, GraphQL::Types::String, null: true,
          method: :def_system_prompt, description: 'System prompt for the agent.'
        field :tools, ::Types::Ai::Catalog::BuiltInToolType.connection_type, null: false,
          description: 'List of GitLab tools enabled for the agent.'
        field :user_prompt, GraphQL::Types::String, null: true,
          method: :def_user_prompt, description: 'User prompt for the agent.'

        def tools
          tool_ids = object.def_tools
          return [] if tool_ids.empty?

          ::Ai::Catalog::BuiltInTool.where(id: tool_ids) # rubocop:disable CodeReuse/ActiveRecord -- Not a database query
        end

        def mcp_servers
          ::Ai::Catalog::McpServersBatchLoader.load_for(object, current_user)
        end
      end
    end
  end
end
