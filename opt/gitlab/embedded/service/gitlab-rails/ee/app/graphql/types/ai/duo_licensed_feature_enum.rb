# frozen_string_literal: true

module Types
  module Ai
    class DuoLicensedFeatureEnum < BaseEnum
      graphql_name 'DuoLicensedFeature'
      description 'List of GitLab Duo licensed features.'

      # Subset of Duo features. Expand as needed.
      # Each value must be a valid feature name from ::GitlabSubscriptions::Features::ALL_FEATURES.
      value 'AGENTIC_CHAT', value: 'agentic_chat', description: 'Agentic Chat feature.'
      value 'AI_CATALOG', value: 'ai_catalog', description: 'AI Catalog feature.'
      value 'AI_FEATURES', value: 'ai_features', description: 'AI features.'
    end
  end
end
