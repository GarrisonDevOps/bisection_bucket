# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class SyncPolicyEventService < BaseProjectPolicyService
      def initialize(project:, security_policy:, event:, defer_policy_mr_sync: false)
        super(project: project, security_policy: security_policy)
        @event = event
        @defer_policy_mr_sync = defer_policy_mr_sync
      end

      def execute
        if policy_disabled_or_scope_inapplicable?
          unlink_policy_if_needed(defer_policy_mr_sync: defer_policy_mr_sync)
        else
          case event
          when Projects::ComplianceFrameworkChangedEvent,
            ::Repositories::ProtectedBranchCreatedEvent,
            ::Repositories::ProtectedBranchDestroyedEvent,
            ::Repositories::DefaultBranchChangedEvent
            converge_policy
          when Projects::SecurityAttributeChangedEvent
            sync_policy_for_security_attribute(event)
          when Security::PolicyResyncEvent
            resync_policy
          end
        end
      end

      private

      def resync_policy
        unlink_policy_if_needed(skip_delete_worker: true, defer_policy_mr_sync: defer_policy_mr_sync)
        link_policy(defer_policy_mr_sync: defer_policy_mr_sync)
      end

      def converge_policy
        link_policy
        # Non-approval policies have no merge request rules to sweep.
        sync_approval_policy_rules if security_policy.type_approval_policy?
      end

      def sync_policy_for_security_attribute(event)
        unless security_policy.policy_scope.references_any_security_attribute?(event.data[:security_attribute_id])
          return
        end

        link_policy
      end

      def unlink_policy_if_needed(**args)
        unlink_policy(**args) if unlink_policy_needed?
      end

      attr_reader :event, :defer_policy_mr_sync
    end
  end
end
