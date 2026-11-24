# frozen_string_literal: true

module Types
  module Analytics
    module AiUsage
      class AiInstanceUsageDataType < BaseObject
        graphql_name 'AiInstanceUsageData'
        description "Instance wide usage data for events stored in either PostgreSQL (default) or ClickHouse " \
          "(when configured). " \
          "Data retention: three months in PostgreSQL, indefinite in ClickHouse. " \
          "Premium and Ultimate only."

        authorize :read_enterprise_ai_analytics

        field :all,
          description: 'All Duo usage events.',
          resolver: ::Resolvers::Analytics::AiUsage::InstanceUsageEventsResolver

        def self.authorized?(_object, ...)
          super(:global, ...)
        end
      end
    end
  end
end
