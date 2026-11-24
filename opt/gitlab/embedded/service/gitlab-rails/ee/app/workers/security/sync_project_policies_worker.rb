# frozen_string_literal: true

module Security
  class SyncProjectPoliciesWorker
    include ApplicationWorker
    prepend ::Geo::SkipSecondary

    data_consistency :sticky

    # No including_scheduled: a duplicate from perform_in would be dropped instead of rescheduled
    deduplicate :until_executed, if_deduplicated: :reschedule_once
    idempotent!
    feature_category :security_policy_management

    concurrency_limit -> { 200 }

    def perform(project_id, policy_configuration_id, params = {})
      project = Project.find_by_id(project_id)
      policy_configuration = Security::OrchestrationPolicyConfiguration.find_by_id(policy_configuration_id)

      return unless project && policy_configuration

      sync_reason = Security::SecurityOrchestrationPolicies::SyncReason.from_params(params)

      if sync_reason == :configuration_assigned
        Security::SecurityOrchestrationPolicies::LinkPolicyConfigurationService.new(
          project: project,
          configuration: policy_configuration
        ).execute
      elsif sync_reason == :force_resync && Feature.enabled?(:state_based_security_policy_resync, :instance)
        Security::SecurityOrchestrationPolicies::ResyncProjectPoliciesService.new(
          project: project,
          configuration: policy_configuration
        ).execute
      else
        policy_configuration.security_policies.undeleted.pluck_primary_key.each do |security_policy_id|
          Security::SyncProjectPolicyWorker.perform_async(
            project.id, security_policy_id, {}, build_policy_payload(sync_reason, security_policy_id)
          )
        end
      end
    end

    private

    def build_policy_payload(sync_reason, security_policy_id)
      return {} unless sync_reason == :force_resync

      { event: { event_type: 'Security::PolicyResyncEvent', data: { security_policy_id: security_policy_id } } }
    end
  end
end
