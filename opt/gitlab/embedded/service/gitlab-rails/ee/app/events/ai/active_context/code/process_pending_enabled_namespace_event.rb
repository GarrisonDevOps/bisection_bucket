# frozen_string_literal: true

module Ai
  module ActiveContext
    module Code
      class ProcessPendingEnabledNamespaceEvent < ::Gitlab::EventStore::CloudEvent
        event_category :ai_active_context_code
        event_type :process_pending_enabled_namespace

        class << self
          def build
            build_cloud_event(
              source: "instance",
              subject: "ai_active_context/code/enabled_namespaces"
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
