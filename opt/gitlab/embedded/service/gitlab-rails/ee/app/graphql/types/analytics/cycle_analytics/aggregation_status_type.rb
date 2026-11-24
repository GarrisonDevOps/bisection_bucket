# frozen_string_literal: true

module Types
  module Analytics
    module CycleAnalytics
      class AggregationStatusType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization is done in the parent type
        field :enabled, ::GraphQL::Types::Boolean,
          description: 'Whether background aggregation is enabled or disabled. ' \
                       'For downgraded, non-licensed groups and projects the field is `false`.',
          null: false
        field :estimated_next_update_at, Types::TimeType,
          description: 'Estimated time when the next incremental update will happen.',
          null: true
        field :last_update_at, Types::TimeType,
          description: 'Last incremental update time.',
          null: true
      end
    end
  end
end
