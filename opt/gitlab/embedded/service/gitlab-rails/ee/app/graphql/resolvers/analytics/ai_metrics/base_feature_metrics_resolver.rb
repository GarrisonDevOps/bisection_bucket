# frozen_string_literal: true

module Resolvers
  module Analytics
    module AiMetrics
      class BaseFeatureMetricsResolver < BaseResolver # rubocop: disable Graphql/ResolverType -- Type defined on subclasses
        include LooksAhead

        # Subclasses must define their own type, e.g.:
        # type ::Types::Analytics::AiMetrics::YourMetricsType, null: true

        def resolve_with_lookahead(**args)
          usage = ::Analytics::AiAnalytics::UsageEventCountService.new(
            current_user,
            namespace: context[:ai_metrics_namespace],
            from: context[:ai_metrics_params][:start_date],
            to: context[:ai_metrics_params][:end_date],
            fields: lookahead.selections.map(&:name),
            **args
          ).execute

          usage.payload
        end
      end
    end
  end
end
