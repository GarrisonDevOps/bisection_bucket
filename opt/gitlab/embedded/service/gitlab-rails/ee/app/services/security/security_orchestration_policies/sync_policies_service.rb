# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class SyncPoliciesService
      include Gitlab::Utils::StrongMemoize

      def initialize(configuration:, params: {})
        @configuration = configuration
        @params = params
      end

      def execute
        configuration.invalidate_policy_yaml_cache

        unless configuration.policy_configuration_valid?
          configuration.delete_all_schedules
          Security::ScanResultPolicies::DeleteScanResultPolicyReadsWorker.perform_async(configuration.id)

          update_configuration_timestamp!
          audit_invalid_policy_yaml if collect_invalid_policy_yaml_event?
          return
        end

        update_experiments_configuration!

        unless full_sync? || configuration.policies_changed?
          update_configuration_timestamp!
          return
        end

        rebuild_rule_schedules if rebuild_rule_schedules?

        update_configuration_timestamp!

        Security::PersistSecurityPoliciesWorker.perform_async(configuration.id, SyncReason.to_params(sync_reason))
      end

      private

      attr_reader :configuration, :params

      def rebuild_rule_schedules
        configuration.delete_all_schedules
        configuration.active_scan_execution_policies.each_with_index do |policy, policy_index|
          Security::SecurityOrchestrationPolicies::ProcessRuleService
            .new(policy_configuration: configuration, policy_index: policy_index, policy: policy)
            .execute
        end
      end

      # Rebuilding cascades to per-project schedules, so keep them when only other policy types changed.
      # `rule_schedules.none?` is needed because the sync after invalid YAML deleted all schedules.
      def rebuild_rule_schedules?
        full_sync? || configuration.rule_schedules.none? || configuration.scan_execution_policies_changed?
      end

      def sync_reason
        Security::SecurityOrchestrationPolicies::SyncReason.from_params(params)
      end
      strong_memoize_attr :sync_reason

      def full_sync?
        sync_reason == :force_resync || sync_reason == :configuration_assigned
      end

      def update_experiments_configuration!
        Security::SecurityOrchestrationPolicies::UpdateExperimentsService.new(
          policy_configuration: configuration
        ).execute
      end

      def audit_invalid_policy_yaml
        Security::SecurityOrchestrationPolicies::CollectPolicyYamlInvalidatedAuditEventService.new(configuration).execute
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e,
          security_policy_management_project_id: configuration.security_policy_management_project.id,
          configuration_id: configuration.id
        )
      end

      def collect_invalid_policy_yaml_event?
        configuration.first_configuration_for_the_management_project?
      end

      def update_configuration_timestamp!
        configuration.update!(configured_at: Time.current)
      end
    end
  end
end
