# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    # Finds or creates the `security_policy` trigger, and its dedicated account, that a scheduled agentic scan runs as.
    class ProvisionAgenticScanTriggerService < ::BaseProjectService
      include ::Gitlab::ExclusiveLeaseHelpers

      LEASE_TTL = 1.minute
      TRIGGER_DESCRIPTION = 'Scan execution policy'

      def execute
        trigger = active_trigger
        # Users cannot deactivate a policy trigger, so an inactive one was stopped on purpose: don't replace it.
        return trigger_response(trigger) if trigger || policy_triggers.exists?

        in_lock(lease_key, ttl: LEASE_TTL, retries: 10, sleep_sec: 0.5.seconds) do
          trigger = active_trigger
          trigger ? trigger_response(trigger) : create_trigger
        end
      rescue ::Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
        error('Could not obtain the lock to provision a policy trigger')
      end

      private

      def item_consumer
        params[:item_consumer]
      end

      def active_trigger
        policy_triggers.active.ordered_by_id.first
      end

      def policy_triggers
        ::Ai::FlowTrigger.for_projects(project.id).by_item_consumer_ids(item_consumer.id)
          .triggered_on(:security_policy)
      end

      def lease_key
        "security_orchestration_policies:agentic_scan_trigger:#{project.id}:#{item_consumer.id}"
      end

      def trigger_response(trigger)
        return error('No active policy trigger with its own service account') unless trigger&.autonomous_service_account

        ServiceResponse.success(payload: { trigger: trigger })
      end

      # Created directly: Ai::FlowTriggers::CreateService needs a user who may manage triggers,
      # which admin_bot is not without a Duo seat, and it refuses the security_policy type.
      def create_trigger
        # A trial needs a verified person to create a service account; a schedule has none.
        return error('Cannot provision a service account during a trial') if project.root_ancestor.trial_active?

        # The flow's account has a composite identity, and a schedule has no human to pair with it.
        flow_account = item_consumer.active_service_account
        unless flow_account &&
            ::Ability.allowed?(flow_account, :execute_ai_catalog_item, item_consumer, composite_identity_check: false)
          return error('The flow cannot run in this project')
        end

        admin_bot = ::Users::Internal.in_organization(project.organization).admin_bot
        return error('Admin bot not found for the project organization') unless admin_bot

        access_level = item_consumer.active_service_account_access_level(project)
        return error("The flow's service account is not a member of this project") unless access_level

        failure = nil
        trigger = ::ApplicationRecord.transaction do
          provisioned = ::Ai::FlowTriggers::ProvisionAutonomousServiceAccountService.new(
            project: project, current_user: admin_bot, item_consumer: item_consumer,
            description: TRIGGER_DESCRIPTION, access_level: access_level, kind: 'Security policy'
          ).execute

          if provisioned.error?
            failure = provisioned.message
            raise ActiveRecord::Rollback
          end

          created = project.ai_flow_triggers.create(
            ai_catalog_item_consumer: item_consumer,
            autonomous_service_account: provisioned.payload[:service_account],
            event_types: [::Ai::FlowTrigger::EVENT_TYPES[:security_policy]],
            description: TRIGGER_DESCRIPTION,
            active: true
          )
          next created if created.persisted?

          failure = created.errors.full_messages.to_sentence
          raise ActiveRecord::Rollback
        end

        return error('Could not provision a policy trigger for agentic scan', error_message: failure) unless trigger

        audit_trigger_created(trigger, admin_bot)
        # The membership is only effective once authorizations refresh; this run must not wait for the worker.
        trigger.autonomous_service_account.refresh_authorized_projects(source: self.class.name)

        ServiceResponse.success(payload: { trigger: trigger })
      end

      def audit_trigger_created(trigger, author)
        ::Gitlab::Audit::Auditor.audit(
          name: 'flow_trigger_created',
          author: author,
          scope: project,
          target: trigger,
          target_details: "#{trigger.description} (ID: #{trigger.id})",
          message: "Flow trigger created for scheduled #{params[:scan]} scans of policy '#{params[:policy_name]}'"
        )
      end

      def error(message, error_message: nil)
        ServiceResponse.error(message: message, payload: { error_message: error_message }.compact)
      end
    end
  end
end
