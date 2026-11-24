# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Cleanup
      # rubocop: disable Graphql/AuthorizeTypes -- authorization handled by parent PolicyType
      class PolicyLastRunDetailedMetricsType < ::Types::BaseObject
        graphql_name 'CleanupPolicyLastRunDetailedMetrics'
        description 'Represents the metrics of the last run virtual registry cleanup policy'

        field :maven, ::Types::VirtualRegistries::Cleanup::PolicyLastRunUpstreamMetricsType, null: true,
          hash_key: 'maven',
          description: 'Last run detail metrics of maven.',
          experiment: { milestone: '18.7' }

        field :container, ::Types::VirtualRegistries::Cleanup::PolicyLastRunUpstreamMetricsType, null: true,
          hash_key: 'container',
          description: 'Last run detail metrics of container.',
          experiment: { milestone: '18.7' }
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
