# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module AdditionalContext
      # Builds agent_platform_trigger_context (schema: json_schemas/agent_platform/agent_platform_trigger_context).
      module TriggerContextBuilder
        def self.build(event_type: nil, triggering_conversation: nil)
          fields = {
            "event_type" => event_type,
            "triggering_conversation" => triggering_conversation
          }.compact_blank

          fields.presence
        end
      end
    end
  end
end
