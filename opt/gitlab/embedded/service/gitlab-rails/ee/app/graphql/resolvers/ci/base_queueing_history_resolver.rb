# frozen_string_literal: true

module Resolvers
  module Ci
    class BaseQueueingHistoryResolver < BaseResolver
      type Types::Ci::QueueingHistoryType, null: true

      argument :from_time, Types::TimeType,
        required: false,
        description: 'Start of the requested time. Defaults to three hours ago.'

      argument :to_time, Types::TimeType,
        required: false,
        description: 'End of the requested time. Defaults to the current time.'

      def resolve(lookahead:, from_time: nil, to_time: nil, runner_type: nil, owner_namespace: nil)
        result = ::Ci::Runners::CollectQueueingHistoryService.new(current_user: current_user,
          percentiles: selected_percentiles(lookahead),
          runner_type: runner_type,
          from_time: from_time,
          to_time: to_time,
          owner_namespace: owner_namespace
        ).execute

        raise Gitlab::Graphql::Errors::ArgumentError, result.message if result.error?

        { time_series: result.payload }
      end

      private

      def selected_percentiles(lookahead)
        ::Ci::Runners::CollectQueueingHistoryService::ALLOWED_PERCENTILES.filter do |p|
          lookahead.selection(:time_series).selects?("p#{p}")
        end
      end
    end
  end
end
