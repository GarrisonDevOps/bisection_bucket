# frozen_string_literal: true

module Types
  module Ai
    class NamespaceSettingsType < BaseObject
      graphql_name 'AiNamespaceSettings'

      authorize :read_namespace

      def self.authorization_scopes
        [:api, :read_api, :ai_workflows]
      end

      field :duo_workflow_mcp_enabled,
        GraphQL::Types::Boolean,
        null: false,
        scopes: [:api, :read_api, :ai_workflows],
        description: 'Indicates whether the namespace has MCP enabled.'

      field :prompt_injection_protection_level,
        ::Types::Ai::PromptInjectionProtectionLevelEnum,
        null: false,
        scopes: [:api, :read_api, :ai_workflows],
        description: 'Level of prompt injection protection for the namespace.'

      field :web_search_enabled,
        GraphQL::Types::Boolean,
        null: false,
        scopes: [:api, :read_api, :ai_workflows],
        description: 'Indicates whether web search is allowed in GitLab Duo Chat for the namespace.'

      field :ai_catalog_restricted_to_group_hierarchy,
        GraphQL::Types::Boolean,
        null: false,
        scopes: [:api, :read_api, :ai_workflows],
        description: "Indicates whether the AI Catalog is restricted to items within the top-level group's hierarchy."
    end
  end
end
