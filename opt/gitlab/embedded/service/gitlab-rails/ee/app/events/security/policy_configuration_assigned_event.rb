# frozen_string_literal: true

module Security
  class PolicyConfigurationAssignedEvent < ::Gitlab::EventStore::CloudEvent
    event_category :security_policy_management
    event_type :policy_configuration_assigned

    class << self
      def build(configuration:)
        build_cloud_event(
          source: "security/orchestration_policy_configurations/#{configuration.id}",
          subject: "security/orchestration_policy_configurations/#{configuration.id}",
          event_data: { configuration_id: configuration.id }
        )
      end
    end

    def data_schema
      {
        type: "object",
        required: %w[configuration_id],
        properties: {
          configuration_id: { type: "integer" }
        },
        additionalProperties: false
      }
    end
  end
end
