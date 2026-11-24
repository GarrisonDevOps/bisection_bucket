# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class MarkRepositoryAsReadyEvent < ::Gitlab::EventStore::CloudEvent
        event_category :ai_active_context_code
        event_type :mark_repository_as_ready

        class << self
          def build
            build_cloud_event(
              source: "instance",
              subject: "ai_active_context/code/repositories"
            )
          end
        end

        def data_schema
          {
            'type' => 'object',
            'properties' => {},
            'additionalProperties' => false
          }
        end
      end
    end
  end
end
