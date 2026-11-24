# frozen_string_literal: true

# Measures time to first token (TTFT) for Duo Chat requests
module Gitlab
  module Metrics
    module LlmChatFirstToken
      include Gitlab::Metrics::SliConfig

      sidekiq_enabled!
      class << self
        def initialize_slis!
          completion = Gitlab::Llm::Utils::AiFeaturesCatalogue::LIST[:chat]
          completion_labels = [
            { feature_category: completion[:feature_category], service_class: completion[:service_class].name }
          ]

          Gitlab::Metrics::Sli::Apdex.initialize_sli(:llm_chat_first_token, completion_labels)
        end
      end
    end
  end
end
