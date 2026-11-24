# frozen_string_literal: true

module Types
  module Analytics
    module AiMetrics
      # rubocop: disable Graphql/AuthorizeTypes -- always authorized by Resolver
      # rubocop: disable GraphQL/ExtractType -- no value for now
      class NamespaceMetricsType < BaseObject
        graphql_name 'AiMetrics'
        description "Requires ClickHouse. Premium and Ultimate only."

        field :agent_platform,
          resolver: Resolvers::Analytics::AiMetrics::AgentPlatformMetricsResolver,
          null: true,
          description: 'Duo Agent Platform metrics.'
        field :chat,
          resolver: Resolvers::Analytics::AiMetrics::DuoChatMetricsResolver,
          null: true,
          description: 'Duo Chat metrics.'
        field :code_contributors_count, GraphQL::Types::Int,
          description: 'Number of code contributors.',
          null: true
        field :code_review,
          resolver: Resolvers::Analytics::AiMetrics::CodeReviewMetricsResolver,
          null: true,
          description: 'Code review metrics.'
        field :code_suggestions,
          resolver: Resolvers::Analytics::AiMetrics::CodeSuggestionMetricsResolver,
          null: true,
          description: 'Code suggestions metrics.'
        field :duo_chat_contributors_count, GraphQL::Types::Int,
          description: 'Number of contributors who used GitLab Duo Chat features.',
          null: true
        field :duo_used_count, GraphQL::Types::Int,
          description: 'Number of contributors who used any GitLab Duo feature.',
          null: true
        field :mcp,
          resolver: Resolvers::Analytics::AiMetrics::McpMetricsResolver,
          null: true,
          description: 'Model Context Protocol metrics.'
        field :root_cause_analysis_users_count, GraphQL::Types::Int,
          description: 'Number of users using troubleshoot within a failed pipeline.',
          null: true
        field :troubleshoot,
          resolver: Resolvers::Analytics::AiMetrics::TroubleshootJobMetricsResolver,
          null: true,
          description: 'Troubleshoot job metrics.'
      end
      # rubocop: enable GraphQL/ExtractType
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
