# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    # Force resyncs all of a configuration's policies to a project in one pass, with one merge request sweep
    class ResyncProjectPoliciesService
      include ProjectWideSyncs

      def initialize(project:, configuration:)
        @project = project
        @configuration = configuration
      end

      def execute
        policies = configuration.security_policies.undeleted.to_a

        resynced = policies.select { |policy| resync_policy(policy) }
        # Applicable policies were relinked with their merge request sweep deferred to here
        relinked = resynced.select { |policy| policy.enabled && policy.scope_applicable?(project) }

        schedule_project_wide_syncs(relinked)
      end

      private

      attr_reader :project, :configuration

      def resync_policy(policy)
        Security::SecurityOrchestrationPolicies::SyncPolicyEventService.new(
          project: project,
          security_policy: policy,
          event: Security::PolicyResyncEvent.new(data: { security_policy_id: policy.id }),
          defer_policy_mr_sync: true
        ).execute

        true
      rescue StandardError => e
        retry_policy_separately(policy, e)
        false
      end

      # The per-policy worker owns the retry: it backs off on transient errors and discards an invalid resync.
      def retry_policy_separately(policy, error)
        Gitlab::ErrorTracking.track_exception(error, security_policy_id: policy.id, project_id: project.id)

        # The delay lets this job finish before the retry touches the same project's rules again.
        Security::SyncProjectPolicyWorker.perform_in(
          1.minute, project.id, policy.id, {},
          { event: { event_type: Security::PolicyResyncEvent.name, data: { security_policy_id: policy.id } } }
        )
      end
    end
  end
end
