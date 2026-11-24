# frozen_string_literal: true

module Types
  module VirtualRegistries
    module Cleanup
      # rubocop: disable Graphql/AuthorizeTypes -- authorization handled by parent PolicyType
      class PolicyLastRunUpstreamMetricsType < ::Types::BaseObject
        graphql_name 'CleanupPolicyLastRunUpstreamMetrics'
        description 'Represents the metrics of the last run virtual registry cleanup policy of an upstream'

        # rubocop:disable GraphQL/ExtractType -- Not worth extracting deleted_* fields into a separate type
        field :deleted_entries_count, GraphQL::Types::Int, null: false,
          hash_key: 'deleted_entries_count',
          description: 'Number of entries deleted.',
          experiment: { milestone: '18.7' }

        field :deleted_size, GraphQL::Types::BigInt, null: false,
          hash_key: 'deleted_size',
          description: 'Size in bytes of data deleted.',
          experiment: { milestone: '18.7' }
        # rubocop:enable GraphQL/ExtractType
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
