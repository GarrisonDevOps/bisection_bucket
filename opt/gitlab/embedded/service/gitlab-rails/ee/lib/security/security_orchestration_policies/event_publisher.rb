# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class EventPublisher
      def initialize(db_policies:, created_policies:, policies_changes:, deleted_policies:, sync_reason: :policy_change)
        @db_policies = db_policies
        @created_policies = created_policies
        @policies_changes = policies_changes
        @deleted_policies = deleted_policies
        @sync_reason = sync_reason
      end

      def publish
        if sync_reason == :force_resync
          # A state-based resync publishes one PolicyConfigurationResyncEvent from PersistSecurityPoliciesWorker instead
          unless Feature.enabled?(:state_based_security_policy_resync, :instance)
            ::Gitlab::EventStore.publish_group(
              db_policies.map do |policy|
                Security::PolicyResyncEvent.new(data: { security_policy_id: policy.id })
              end
            )
          end
        else
          # On configuration_assigned, only created_policies can exist, so only created events
          # need to carry the triggered_by_assign flag
          ::Gitlab::EventStore.publish_group(
            created_policies.map { |policy| Security::PolicyCreatedEvent.new(data: created_event_data(policy)) }
          )

          ::Gitlab::EventStore.publish_group(
            policies_changes.map do |policy_changes|
              Security::PolicyUpdatedEvent.new(data: policy_changes.event_payload)
            end
          )
        end

        ::Gitlab::EventStore.publish_group(
          deleted_policies.map { |policy| Security::PolicyDeletedEvent.new(data: { security_policy_id: policy.id }) }
        )
      end

      private

      attr_accessor :created_policies, :policies_changes, :deleted_policies, :db_policies, :sync_reason

      def created_event_data(policy)
        data = { security_policy_id: policy.id }
        data[:triggered_by_assign] = true if sync_reason == :configuration_assigned

        data
      end
    end
  end
end
