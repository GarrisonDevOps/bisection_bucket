# frozen_string_literal: true

module Types
  module Analytics
    module AiUsage
      class AiUsageEventFeatureEnum < BaseEnum
        graphql_name 'AiUsageEventFeature'
        description 'Associated Duo feature of AI usage event'

        Gitlab::Tracking::AiTracking.registered_features.each do |feature|
          value feature.upcase, value: feature, description: "Duo #{feature}"
        end
      end
    end
  end
end
