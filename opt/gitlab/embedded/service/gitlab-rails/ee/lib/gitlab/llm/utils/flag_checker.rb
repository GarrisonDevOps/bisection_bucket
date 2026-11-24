# frozen_string_literal: true

module Gitlab
  module Llm
    module Utils
      class FlagChecker
        def self.flag_enabled_for_feature?(method)
          is_chat = method.eql?(:chat)
          # rubocop:disable Gitlab/FeatureFlagWithoutActor -- those are ops flags
          # Chat is now always enabled
          return true if is_chat

          return true if method.in?(::Gitlab::Llm::Utils::AiFeaturesCatalogue.for_saas_and_sm.keys)

          return true if Feature.enabled?(:ai_global_switch, type: :ops) &&
            method.in?(::Gitlab::Llm::Utils::AiFeaturesCatalogue.for_saas_only.keys)

          # rubocop:enable Gitlab/FeatureFlagWithoutActor
          false
        end
      end
    end
  end
end
