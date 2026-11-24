# frozen_string_literal: true

# rubocop:disable Graphql/ResolverType -- inherited from Resolvers::Analytics::CycleAnalytics::BaseIssueResolver
module Resolvers
  module Analytics
    module CycleAnalytics
      class TimeToMergeResolver < BaseMergeRequestStageResolver
        METRIC_CLASS = Gitlab::Analytics::CycleAnalytics::Summary::TimeToMerge

        private

        def formatted_data(metric)
          super.merge(
            identifier: :time_to_merge,
            title: _('Time to Merge')
          )
        end
      end
    end
  end
end
# rubocop:enable Graphql/ResolverType
