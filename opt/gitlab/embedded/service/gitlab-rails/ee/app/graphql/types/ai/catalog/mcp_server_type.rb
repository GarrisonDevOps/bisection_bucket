# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class McpServerType < ::Types::BaseObject
        graphql_name 'AiCatalogMcpServer'

        include ::Gitlab::Graphql::Authorize::AuthorizeResource

        description 'An MCP (Model Context Protocol) server'
        authorize :read_ai_catalog_mcp_server
        authorize_granular_token permissions: :read_ai_catalog_mcp_server, boundary: :user, boundary_type: :user

        field :id,
          GraphQL::Types::ID,
          null: false,
          description: 'ID of the MCP server.'

        field :name,
          GraphQL::Types::String,
          null: false,
          description: 'Name of the MCP server.'

        field :description,
          GraphQL::Types::String,
          null: true,
          description: 'Description of the MCP server.'

        field :url,
          GraphQL::Types::String,
          null: false,
          description: 'URL of the MCP server.'

        field :homepage_url,
          GraphQL::Types::String,
          null: true,
          description: 'Homepage URL of the MCP server.'

        field :transport,
          Types::Ai::Catalog::McpServerTransportEnum,
          null: false,
          description: 'Transport type for the MCP server.'

        field :auth_type,
          Types::Ai::Catalog::McpServerAuthTypeEnum,
          null: false,
          description: 'Authentication type for the MCP server.'

        field :oauth_client_id,
          GraphQL::Types::String,
          null: true,
          description: 'OAuth client ID for the MCP server.'

        field :created_at,
          Types::TimeType,
          null: false,
          description: 'Timestamp when the MCP server was created.'

        field :updated_at,
          Types::TimeType,
          null: false,
          description: 'Timestamp when the MCP server was last updated.'

        field :organization,
          Types::Organizations::OrganizationType,
          null: false,
          description: 'Organization that owns the MCP server.'

        field :current_user_connected,
          GraphQL::Types::Boolean,
          null: false,
          description: 'Whether the current user has connected to the MCP server.'

        field :block_status,
          Types::Ai::Catalog::McpServerBlockStatusEnum,
          null: false,
          description: 'Block status of the MCP server for the given group or project ' \
            '(kill-switch state). Provide exactly one of `groupFullPath` or `projectFullPath`.' do
          # rubocop:disable Graphql/IDType -- Full path identifier, not a global ID
          argument :group_full_path,
            GraphQL::Types::ID,
            required: false,
            description: 'Full path of the group to resolve the block status for.'
          argument :project_full_path,
            GraphQL::Types::ID,
            required: false,
            description: 'Full path of the project to resolve the block status for.'
          # rubocop:enable Graphql/IDType
        end

        def current_user_connected
          object.connected_by_user?(context[:current_user])
        end

        def block_status(group_full_path: nil, project_full_path: nil)
          if group_full_path.present? && project_full_path.present?
            raise ::Gitlab::Graphql::Errors::ArgumentError,
              'Provide only one of groupFullPath or projectFullPath.'
          end

          # No scope requested (for example, introspection or auto-generated queries): default to ACTIVE.
          unless group_full_path.present? || project_full_path.present?
            return ::Ai::Catalog::McpServerBlockStatusBatchLoader::ACTIVE
          end

          container = authorized_container(group_full_path: group_full_path, project_full_path: project_full_path)
          unless container
            raise_resource_not_available_error!(
              'Group or project was not found, or you do not have permission to access it.'
            )
          end

          ::Ai::Catalog::McpServerBlockStatusBatchLoader.load_for(object, block_namespace_for(container))
        end

        private

        def authorized_container(group_full_path:, project_full_path:)
          if project_full_path.present?
            find_authorized_container(project_full_path, ::Project, :read_project)
          elsif group_full_path.present?
            find_authorized_container(group_full_path, ::Group, :read_group)
          end
        end

        def find_authorized_container(full_path, klass, ability)
          context[:mcp_block_status_containers] ||= {}
          cache_key = [klass.name, full_path]

          if context[:mcp_block_status_containers].key?(cache_key)
            return context[:mcp_block_status_containers][cache_key]
          end

          container = klass.find_by_full_path(full_path)
          container = nil unless container && Ability.allowed?(context[:current_user], ability, container)

          context[:mcp_block_status_containers][cache_key] = container
        end

        # Project blocks are stored against the project's project-namespace so the shared ancestry
        # resolution (group + descendants) treats them uniformly with group blocks.
        def block_namespace_for(container)
          container.is_a?(::Project) ? container.project_namespace : container
        end
      end
    end
  end
end
