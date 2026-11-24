# frozen_string_literal: true

module Resolvers
  module Analytics
    module AiMetrics
      class TroubleshootJobMetricsResolver < BaseFeatureMetricsResolver # rubocop: disable Graphql/ResolverType -- false positive
        type ::Types::Analytics::AiMetrics::TroubleshootJobMetricsType, null: true
      end
    end
  end
end
