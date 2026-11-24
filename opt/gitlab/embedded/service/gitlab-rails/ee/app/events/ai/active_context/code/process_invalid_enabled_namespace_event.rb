# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class ProcessInvalidEnabledNamespaceEvent < ::Gitlab::EventStore::CloudEvent
        event_category :ai_active_context_code
        event_type :process_invalid_enabled_namespace

        class << self
          def build(last_processed_id: nil)
            build_cloud_event(
              source: "instance",
              subject: "ai_active_context/code/enabled_namespaces",
              event_data: { last_processed_id: last_processed_id }
            )
          end
        end

        def data_schema
          {
            'type' => 'object',
            'properties' => {
              'last_processed_id' => { 'type' => %w[integer null] }
            },
            'additionalProperties' => false
          }
        end
      end
    end
  end
end
