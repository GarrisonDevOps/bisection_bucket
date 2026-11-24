# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class AuditWarnModeGroupProtectedBranchesOverridesWorker
      include Gitlab::EventStore::Subscriber

      data_consistency :sticky

      # This worker isn't idempotent because policy edits can't be told apart by
      # their identity. However `EventStore::Subscriber` enforces the idempotency
      # attribute.
      idempotent!

      feature_category :security_policy_management

      def handle_event(event)
        security_policy_id = event.data[:security_policy_id]
        policy = Security::Policy.find_by_id(security_policy_id) || return

        return unless policy.enabled? && create_audit_event?(event)

        policy.security_orchestration_policy_configuration.all_top_level_group_ids do |group_ids|
          next if group_ids.empty?

          ::Security::ScanResultPolicies::AuditWarnModeGroupProtectedBranchesOverridesGroupWorker
            .bulk_perform_async_with_contexts(
              group_ids,
              arguments_proc: ->(group_id) { [group_id] },
              context_proc: ->(_) { { namespace: policy.security_orchestration_policy_configuration.namespace } }
            )
        end
      end

      private

      def create_audit_event?(event)
        diff = event.data[:diff]

        case event
        when Security::PolicyCreatedEvent then true
        when Security::PolicyUpdatedEvent then relevant_approval_settings_changed?(diff)
        else raise "Unrecognized event type: #{event.class.name}"
        end
      end

      def relevant_approval_settings_changed?(diff)
        return true if diff.key?(:enabled)

        setting_changed?(diff, "block_branch_modification") || setting_changed?(diff, "block_group_branch_modification")
      end

      def setting_changed?(diff, setting_name)
        from_value = diff.dig("approval_settings", "from", setting_name)
        to_value = diff.dig("approval_settings", "to", setting_name)

        from_value != to_value
      end
    end
  end
end
