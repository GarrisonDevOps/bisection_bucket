# frozen_string_literal: true

module Resolvers
  module Analytics
    module ValueStreamDashboard
      class CountResolver < BaseResolver
        include CommonCountResolverMethods

        type ::Types::Analytics::ValueStreamDashboard::CountType, null: true

        authorize :read_group_analytics_dashboards

        argument :identifier, Types::Analytics::ValueStreamDashboard::MetricEnum,
          required: true,
          description: 'Type of counts to retrieve.'
      end
    end
  end
end
