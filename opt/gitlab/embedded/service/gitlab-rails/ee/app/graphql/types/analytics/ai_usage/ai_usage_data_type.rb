# frozen_string_literal: true

module Types
  module Analytics
    module AiUsage
      class AiUsageDataType < BaseObject
        graphql_name 'AiUsageData'
        description "Usage data for events stored in either PostgreSQL (default) or ClickHouse (when configured). " \
          "Data retention: three months in PostgreSQL, indefinite in ClickHouse. " \
          "Requires a personal access token. Works only on top-level groups. " \
          "Premium and Ultimate only."

        authorize :read_enterprise_ai_analytics

        field :code_suggestion_events,
          description: 'Events related to code suggestions.',
          resolver: ::Resolvers::Analytics::AiUsage::CodeSuggestionEventsResolver

        field :all,
          description: 'All Duo usage events.',
          resolver: ::Resolvers::Analytics::AiUsage::UsageEventsResolver
      end
    end
  end
end
