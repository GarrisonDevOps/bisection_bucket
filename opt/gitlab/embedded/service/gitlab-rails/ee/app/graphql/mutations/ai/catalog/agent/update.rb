# frozen_string_literal: true

module Mutations
  module Ai
    module Catalog
      module Agent
        class Update < BaseMutation
          graphql_name 'AiCatalogAgentUpdate'

          include ::Mutations::Ai::Catalog::ConfigValidationRateLimitable

          field :item,
            ::Types::Ai::Catalog::AgentType,
            null: true,
            description: 'Agent that was updated.'

          argument :id, ::Types::GlobalIDType[::Ai::Catalog::Item],
            required: true,
            description: 'Global ID of the catalog Agent to update.'

          argument :description, GraphQL::Types::String,
            required: false,
            description: 'Description for the agent.'

          argument :name, GraphQL::Types::String,
            required: false,
            description: 'Name for the agent.'

          argument :public, GraphQL::Types::Boolean,
            required: false,
            deprecated: { reason: 'Use `visibility`', milestone: '19.2' },
            description: 'Whether the agent is publicly visible in the catalog.'

          argument :visibility, ::Types::Ai::Catalog::ItemVisibilityEnum,
            required: false,
            experiment: { milestone: '19.2' },
            description: 'Visibility of the agent in the catalog.'

          argument :release, GraphQL::Types::Boolean,
            required: false,
            description: 'Whether to release the latest version of the agent.'

          argument :system_prompt, GraphQL::Types::String,
            required: false,
            description: 'System prompt for the agent.'

          argument :tools, [::Types::GlobalIDType[::Ai::Catalog::BuiltInTool]], # rubocop:disable Graphql/ForbiddenLoadsArgument -- pre-existing code; removing `loads:` would be a breaking change
            required: false,
            loads: Types::Ai::Catalog::BuiltInToolType,
            description: 'List of GitLab built-in tools enabled for the agent.'

          argument :mcp_tools, [GraphQL::Types::String],
            required: false,
            description: 'List of MCP tools enabled for the agent.',
            experiment: { milestone: '18.11' }

          argument :user_prompt, GraphQL::Types::String,
            required: false,
            description: 'User prompt for the agent.'

          argument :version_bump, Types::Ai::Catalog::VersionBumpEnum,
            required: false,
            description: 'Bump version, calculated from the last released version name.'

          argument :mcp_servers, [::Types::GlobalIDType[::Ai::Catalog::McpServer]],
            required: false,
            description: "MCP servers to associate with the agent. At most #{::Ai::Catalog::ItemVersion::MCP_SERVERS_LIMIT}.",
            experiment: { milestone: '18.10' },
            validates: { length: { maximum: ::Ai::Catalog::ItemVersion::MCP_SERVERS_LIMIT } },
            prepare: ->(global_ids, _ctx) do
              global_ids.map do |gid|
                GitlabSchema.parse_gid(gid, expected_type: ::Ai::Catalog::McpServer).model_id.to_i
              end
            end

          authorize :admin_ai_catalog_item
          authorize_granular_token permissions: :update_ai_catalog_agent,
            boundary_argument: :id, boundary: :project, boundary_type: :project

          validates mutually_exclusive: [:public, :visibility]

          def resolve(args)
            agent = authorized_find!(id: args.delete(:id))

            return { item: nil, errors: [config_validation_rate_limited_message] } if config_validation_rate_limited?

            params = args.merge(item: agent)

            result = ::Ai::Catalog::Agents::UpdateService.new(
              project: agent.project,
              current_user: current_user,
              params: params
            ).execute

            item = result.payload[:item]
            item.reset

            {
              item: item,
              errors: result.errors
            }
          end
        end
      end
    end
  end
end
