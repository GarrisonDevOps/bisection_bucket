# frozen_string_literal: true

module Resolvers
  module Analytics
    module AiMetrics
      class McpMetricsResolver < BaseFeatureMetricsResolver # rubocop: disable Graphql/ResolverType -- false positive
        type ::Types::Analytics::AiMetrics::McpMetricsType, null: true
      end
    end
  end
end
