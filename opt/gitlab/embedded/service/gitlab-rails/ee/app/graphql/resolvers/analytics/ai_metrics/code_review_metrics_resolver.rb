# frozen_string_literal: true

module Resolvers
  module Analytics
    module AiMetrics
      class CodeReviewMetricsResolver < BaseFeatureMetricsResolver # rubocop: disable Graphql/ResolverType -- false positive
        type ::Types::Analytics::AiMetrics::CodeReviewMetricsType, null: true
      end
    end
  end
end
