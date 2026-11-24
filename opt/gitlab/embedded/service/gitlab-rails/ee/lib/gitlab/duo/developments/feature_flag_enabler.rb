# frozen_string_literal: true

module Gitlab
  module Duo
    module Developments
      class FeatureFlagEnabler
        # list of feature flags from these groups to ignore in development environments
        EXCLUDED_FEATURE_FLAGS = %i[
          incident_fail_over_completion_provider
          incident_fail_over_generation_provider

          # Model-specific feature flags disabled by default as they require specific configuration
          duo_agentic_chat_openai_gpt_5 # Ref: https://gitlab.com/gitlab-org/gitlab/-/issues/560561
        ].freeze

        AI_FEATURE_FLAG_GROUPS = [
          'group::ai framework',
          'group::agent foundations',
          'group::duo chat',
          'group::duo workflow',
          'group::custom models',
          'group::ai coding'
        ].freeze

        def self.execute
          feature_flag_names = Feature::Definition.definitions.filter_map do |name, definition|
            next if definition.wip?

            name if AI_FEATURE_FLAG_GROUPS.include?(definition.group)
          end

          feature_flag_names = feature_flag_names.flatten - EXCLUDED_FEATURE_FLAGS

          feature_flag_names.each do |ff|
            puts "Enabling the feature flag: #{ff}"
            Feature.enable(ff.to_sym)
          end
        end
      end
    end
  end
end
