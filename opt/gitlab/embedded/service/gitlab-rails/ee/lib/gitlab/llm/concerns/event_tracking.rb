# frozen_string_literal: true

module Gitlab
  module Llm
    module Concerns
      module EventTracking
        extend ActiveSupport::Concern

        def track_prompt_size(token_size, provider = nil)
          Gitlab::Tracking.event(
            tracking_class_name(provider),
            "tokens_per_user_request_prompt",
            label: tracking_context[:action].to_s,
            property: tracking_context[:request_id],
            user: user,
            value: token_size
          )
        end

        def track_response_size(token_size, provider = nil)
          Gitlab::Tracking.event(
            tracking_class_name(provider),
            "tokens_per_user_request_response",
            label: tracking_context[:action].to_s,
            property: tracking_context[:request_id],
            user: user,
            value: token_size
          )
        end

        def track_embedding_size(token_size)
          Gitlab::Tracking.event(
            tracking_class_name(nil),
            "tokens_per_embedding",
            label: tracking_context[:action].to_s,
            property: tracking_context[:request_id],
            user: user,
            value: token_size
          )
        end

        def tracking_class_name(_provider)
          self.class.to_s
        end
      end
    end
  end
end
