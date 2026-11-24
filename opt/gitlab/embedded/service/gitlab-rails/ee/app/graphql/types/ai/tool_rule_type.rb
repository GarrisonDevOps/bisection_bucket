# frozen_string_literal: true

module Types
  module Ai
    # rubocop: disable Graphql/AuthorizeTypes -- parent authorization is enough
    class ToolRuleType < Types::BaseObject
      graphql_name 'AiToolRule'
      description 'A governance rule for an AI agent tool'

      authorize_granular_token skip_reason: :parent_authorizes

      field :id, # rubocop: disable GraphQL/FieldHashKey -- BaseObject#id calls to_global_id on plain hashes; explicit override required
        GraphQL::Types::ID,
        null: false,
        description: 'Tool name. Used as stable identifier. Always the tool name string and never a database ID.'

      field :name,
        GraphQL::Types::String,
        null: false,
        description: 'Name of the tool as registered in the tool registry.'

      field :action_type,
        Types::Ai::ToolActionTypeEnum,
        null: false,
        description: 'Action type categorisation for the tool.'

      field :category,
        GraphQL::Types::String,
        null: false,
        description: 'Display category for the tool. For example, GitLab Read, Files, and Commands.'

      field :source,
        Types::Ai::ToolSourceEnum,
        null: false,
        description: 'Source of the tool. Either "gitlab" or "mcp". "mcp" covers tools from the GitLab MCP server ' \
          "and from a GitLab client's local MCP server, such as the GitLab Duo CLI."

      field :web_access,
        Types::Ai::ToolPermissionEnum,
        null: true,
        description: 'Effective permission mode for web surface, after applying group and project rules ' \
          'and the default.'

      field :local_access,
        Types::Ai::ToolPermissionEnum,
        null: true,
        description: 'Effective permission mode for local or IDE surface, after applying group and project ' \
          'rules and the default.'

      field :background_access,
        Types::Ai::BackgroundToolPermissionEnum,
        null: true,
        experiment: { milestone: '19.3' },
        description: 'Effective permission mode for the background-flow surface, after applying group and ' \
          'project rules and the default.'

      field :configured_access,
        Types::Ai::ToolRuleAccessType,
        null: false,
        experiment: { milestone: '19.5' },
        description: 'Permission modes set at the requested scope: the project when a project path is given, ' \
          'otherwise the namespace. A null mode is not set at that scope.'

      field :default_access,
        Types::Ai::ToolRuleAccessType,
        null: false,
        experiment: { milestone: '19.5' },
        description: 'Permission modes that apply when no rule is set.'

      def id
        object[:id]
      end

      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
