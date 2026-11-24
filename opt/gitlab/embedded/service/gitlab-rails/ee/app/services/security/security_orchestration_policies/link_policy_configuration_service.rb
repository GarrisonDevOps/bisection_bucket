# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    # Syncs a configuration's policies to a project
    class LinkPolicyConfigurationService
      include ProjectWideSyncs

      def initialize(project:, configuration:)
        @project = project
        @configuration = configuration
      end

      def execute
        linked_policies, failed_policies = applicable_policies.partition { |policy| link_policy(policy) }

        schedule_project_wide_syncs(linked_policies)

        log_result(linked_policies, failed_policies)

        ServiceResponse.success(
          payload: { linked_policy_ids: linked_policies.map(&:id), failed_policy_ids: failed_policies.map(&:id) }
        )
      end

      private

      attr_reader :project, :configuration

      def applicable_policies
        configuration.security_policies.undeleted.enabled.select { |policy| policy.scope_applicable?(project) }
      end

      def link_policy(policy)
        Security::SecurityOrchestrationPolicies::SyncProjectService.new(
          security_policy: policy,
          project: project,
          policy_changes: {},
          defer_policy_mr_sync: true
        ).execute

        true
      rescue ActiveRecord::RecordInvalid => e
        Gitlab::ErrorTracking.track_exception(e, security_policy_id: policy.id, project_id: project.id)
        # An invalid policy is handed to the per-policy worker which repairs RecordInvalid error via its resync path
        Security::SyncProjectPolicyWorker.perform_async(project.id, policy.id)

        false
      end

      def log_result(linked_policies, failed_policies)
        Gitlab::AppJsonLogger.info(
          event: 'link_policy_configuration',
          project_id: project.id,
          configuration_id: configuration.id,
          linked_policy_ids: linked_policies.map(&:id),
          failed_policy_ids: failed_policies.map(&:id)
        )
      end
    end
  end
end
