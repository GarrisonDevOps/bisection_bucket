# frozen_string_literal: true

module Resolvers
  module Analytics
    module AiMetrics
      class DuoChatMetricsResolver < BaseFeatureMetricsResolver # rubocop: disable Graphql/ResolverType -- false positive
        type ::Types::Analytics::AiMetrics::DuoChatMetricsType, null: true
      end
    end
  end
end
