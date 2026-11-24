# frozen_string_literal: true

module Mutations
  module Ai
    module Catalog
      module McpServer
        class SetBlock < BaseMutation
          graphql_name 'AiCatalogMcpServerSetBlock'
          description 'Blocks or allows an external MCP server for a group or project (kill-switch).'

          field :mcp_server,
            ::Types::Ai::Catalog::McpServerType,
            null: true,
            description: 'MCP server with its updated block status.'

          argument :id, ::Types::GlobalIDType[::Ai::Catalog::McpServer],
            required: true,
            description: 'Global ID of the MCP server.'

          # rubocop:disable Graphql/IDType -- Full path identifier, consistent with the matching block_status arguments
          argument :group_full_path, GraphQL::Types::ID,
            required: false,
            description: 'Full path of the group to block or allow the MCP server for. ' \
              'Provide exactly one of `groupFullPath` or `projectFullPath`.'

          argument :project_full_path, GraphQL::Types::ID,
            required: false,
            description: 'Full path of the project to block or allow the MCP server for. ' \
              'Provide exactly one of `groupFullPath` or `projectFullPath`.'
          # rubocop:enable Graphql/IDType

          argument :blocked, GraphQL::Types::Boolean,
            required: true,
            description: 'Set to true to block the MCP server, false to allow it.'

          authorize :read_ai_catalog_mcp_server
          authorize_granular_token permissions: :block_ai_catalog_mcp_server,
            boundaries: [
              { boundary_argument: :group_full_path, boundary_type: :group },
              { boundary_argument: :project_full_path, boundary_type: :project }
            ]

          def resolve(id:, blocked:, group_full_path: nil, project_full_path: nil)
            unless group_full_path.present? ^ project_full_path.present?
              raise ::Gitlab::Graphql::Errors::ArgumentError,
                'Provide exactly one of groupFullPath or projectFullPath.'
            end

            mcp_server = authorized_find!(id: id)
            container = authorized_container(group_full_path: group_full_path, project_full_path: project_full_path)

            # Indistinguishable for "does not exist" and "exists but you lack access", so the mutation
            # cannot be used to enumerate private groups or projects.
            unless container
              raise_resource_not_available_error!(
                'Group or project was not found, or you do not have permission to access it.'
              )
            end

            result = ::Ai::Catalog::McpServers::SetBlockService.new(
              container: container,
              mcp_server: mcp_server,
              current_user: current_user,
              blocked: blocked
            ).execute

            {
              mcp_server: result.success? ? result.payload[:mcp_server] : nil,
              errors: result.errors
            }
          end

          private

          def authorized_container(group_full_path:, project_full_path:)
            if project_full_path.present?
              find_authorized(::Project, project_full_path, :read_project)
            else
              find_authorized(::Group, group_full_path, :read_group)
            end
          end

          def find_authorized(klass, full_path, ability)
            container = klass.find_by_full_path(full_path)
            return unless container && ::Ability.allowed?(current_user, ability, container)

            container
          end
        end
      end
    end
  end
end
