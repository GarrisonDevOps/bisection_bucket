# frozen_string_literal: true

module Types
  module Ci
    # rubocop: disable Graphql/AuthorizeTypes
    # this represents a hash, from the computed percentiles query
    class JobsStatisticsType < BaseObject
      graphql_name 'CiJobsStatistics'
      description 'Statistics for a group of CI jobs.'

      field :queued_duration, DurationStatisticsType,
        null: true,
        description:
          "Statistics for the amount of time that jobs were waiting to be picked up. The calculation is based " \
          "on the #{Resolvers::Ci::RunnersJobsStatisticsResolver::JOBS_LIMIT} most recent jobs run " \
          "by the #{Resolvers::Ci::RunnersJobsStatisticsResolver::RUNNERS_LIMIT} most recently created runners " \
          "in context. If no filter is applied to runners, the calculation uses the " \
          "#{Resolvers::Ci::RunnersJobsStatisticsResolver::JOBS_LIMIT} most recent jobs globally. " \
          "Jobs from older CI partitions might be excluded."

      def queued_duration
        object.object[:queued_duration]
      end
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
