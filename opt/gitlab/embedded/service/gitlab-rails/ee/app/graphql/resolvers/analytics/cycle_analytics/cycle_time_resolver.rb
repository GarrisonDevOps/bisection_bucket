# frozen_string_literal: true

# rubocop:disable Graphql/ResolverType -- inherited from Resolvers::Analytics::CycleAnalytics::BaseIssueResolver
module Resolvers
  module Analytics
    module CycleAnalytics
      class CycleTimeResolver < BaseIssueStageResolver
        METRIC_CLASS = Gitlab::Analytics::CycleAnalytics::Summary::CycleTime

        private

        def formatted_data(metric)
          super.merge(
            identifier: :cycle_time,
            title: _('Cycle time')
          )
        end
      end
    end
  end
end
# rubocop:enable Graphql/ResolverType
