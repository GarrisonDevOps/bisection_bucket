# frozen_string_literal: true

module Types
  module Ci
    # rubocop: disable Graphql/AuthorizeTypes -- authorization is done at the resolver level in the context of the
    # parent object (group or instance/global)
    class QueueingHistoryType < BaseObject
      graphql_name 'QueueingDelayHistory'
      description 'Aggregated statistics about queueing times for CI jobs'

      field :time_series,
        [Types::Ci::QueueingHistoryTimeSeriesType],
        null: true,
        description: 'Time series.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
