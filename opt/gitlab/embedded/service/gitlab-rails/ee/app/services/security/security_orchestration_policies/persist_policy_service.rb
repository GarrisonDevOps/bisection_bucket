# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class PersistPolicyService
      include BaseServiceUtility
      include Gitlab::Loggable
      include Gitlab::Utils::StrongMemoize
      include Gitlab::InternalEventsTracking

      POLICY_TYPE_ALIAS = {
        scan_result_policy: :approval_policy
      }.freeze

      DEPENDENCY_FIREWALL_ENFORCEMENT_VALUES = {
        'enforced' => 1,
        'warn' => 0
      }.freeze

      def initialize(policy_configuration:, policies:, policy_type:, sync_reason: :policy_change)
        @policy_configuration = policy_configuration
        @policies = policies
        @policy_type = POLICY_TYPE_ALIAS[policy_type] || policy_type
        @sync_reason = sync_reason
        raise ArgumentError, "unrecognized policy_type" unless Security::Policy.types.symbolize_keys.key?(@policy_type)
      end

      def execute
        Gitlab::AppJsonLogger.debug(
          build_structured_payload(
            security_orchestration_policy_configuration_id: policy_configuration.id,
            policy_type: policy_type,
            message: 'Starting security policy persistence'
          )
        )

        new_policies, deleted_policies, policies_changes, rearranged_policies = policy_configuration.policy_changes(
          db_policies, policies
        )
        created_policies = []
        updated_policies = []

        ApplicationRecord.transaction do
          mark_policies_for_deletion(deleted_policies)
          update_rearranged_policies(rearranged_policies)
          created_policies = create_policies(new_policies)
          updated_policies = update_policies(policies_changes)
        end

        Gitlab::AppJsonLogger.debug(
          build_structured_payload(
            security_orchestration_policy_configuration_id: policy_configuration.id,
            policy_type: policy_type,
            new_policies_count: new_policies.size,
            deleted_policies_count: deleted_policies.size,
            updated_policies_count: policies_changes.size,
            rearranged_policies_count: rearranged_policies.size,
            message: 'security policy persisted'
          )
        )

        if collect_audit_events_for_the_config?
          CollectPoliciesAuditEvents.new(
            policy_configuration: policy_configuration,
            created_policies: created_policies,
            updated_policies: updated_policies,
            deleted_policies: deleted_policies
          ).execute
        end

        track_approval_policy_feature_usage(:create, created_policies)
        track_approval_policy_feature_usage(:update, updated_policies)

        track_dependency_firewall_policy_rule_changes(
          created_policies: created_policies,
          policies_changes: policies_changes,
          deleted_policies: deleted_policies
        )

        Security::SecurityOrchestrationPolicies::EventPublisher.new(
          db_policies: db_policies.undeleted,
          created_policies: created_policies,
          policies_changes: policies_changes,
          deleted_policies: deleted_policies,
          sync_reason: sync_reason
        ).publish
      end

      private

      attr_reader :policy_configuration, :policies, :policy_type, :sync_reason

      delegate :security_policies, to: :policy_configuration

      def db_policies
        policy_configuration.security_policies.undeleted.merge(relation_scope)
      end
      strong_memoize_attr :db_policies

      def create_policies(new_policies)
        new_policies.map do |policy_hash, index|
          Security::Policy.upsert_policy(policy_type, security_policies, policy_hash, index, policy_configuration)
        end
      end

      def update_policies(policies_changes)
        return [] if policies_changes.empty?

        Security::SecurityOrchestrationPolicies::UpdateSecurityPoliciesService.new(
          policies_changes: policies_changes
        ).execute
      end

      def mark_policies_for_deletion(deleted_policies)
        Security::Policy.soft_delete_all!(deleted_policies)
      end

      # Updates in two steps to avoid unique constraint violations
      def update_rearranged_policies(rearranged_policies)
        return if rearranged_policies.empty?

        temp_index_start = all_db_policies.next_deletion_index
        rearranged_policies.each_with_index do |(policy, _), temp_index|
          policy.update!(policy_index: -(temp_index_start + temp_index))
        end

        rearranged_policies.each do |policy, new_index|
          policy.update!(policy_index: new_index)
        end
      end

      # Includes soft-deleted policies (negative policy_index) so assigned negative
      # indexes never collide with them. See https://gitlab.com/gitlab-org/gitlab/-/issues/600862
      def all_db_policies
        security_policies.merge(relation_scope)
      end

      def relation_scope
        case policy_type
        when :approval_policy then Security::Policy.type_approval_policy
        when :scan_execution_policy then Security::Policy.type_scan_execution_policy
        when :pipeline_execution_policy then Security::Policy.type_pipeline_execution_policy
        when :vulnerability_management_policy then Security::Policy.type_vulnerability_management_policy
        when :pipeline_execution_schedule_policy then Security::Policy.type_pipeline_execution_schedule_policy
        when :dependency_firewall_policy then Security::Policy.type_dependency_firewall_policy
        end
      end

      def collect_audit_events_for_the_config?
        policy_configuration.first_configuration_for_the_management_project?
      end

      def track_approval_policy_feature_usage(action, policies)
        return unless policy_type == :approval_policy
        return if policies.empty?

        features = detect_rule_features(policies)

        track_policy_event("approval_policy_with_enrichment_filters", action) if features[:enrichment_filters]
        track_policy_event("approval_policy_with_atomic_scanner_rule", action) if features[:scanner_overrides]
      end

      def detect_rule_features(policies)
        result = { enrichment_filters: false, scanner_overrides: false }

        policies.each do |policy|
          policy.approval_policy.rules.rules.each do |rule|
            result[:enrichment_filters] ||= rule.has_enrichment_filters?
            result[:scanner_overrides] ||= rule.has_scanner_overrides?
            return result if result.values.all?
          end
        end

        result
      end

      def track_policy_event(event, action)
        track_internal_event(
          event,
          project: policy_configuration.project,
          namespace: policy_configuration.namespace,
          additional_properties: { label: action.to_s }
        )
      end

      def track_dependency_firewall_policy_rule_changes(created_policies:, policies_changes:, deleted_policies:)
        return unless policy_type == :dependency_firewall_policy

        Gitlab::InternalEvents.with_batched_redis_writes do
          created_policies.each do |policy|
            content = policy.policy_content
            enforcement = content[:enforcement_type]
            Array.wrap(content[:rules]).each do |rule|
              emit_dependency_firewall_rule_event(action: 'create',
                rule_type: rule[:type], enforcement_type: enforcement)
            end
          end

          policies_changes.each do |policy_changes|
            enforcement = policy_changes.yaml_policy[:enforcement_type]
            rules_diff = policy_changes.diff.rules_diff

            rules_diff.created.each do |rule_diff|
              emit_dependency_firewall_rule_event(action: 'create',
                rule_type: rule_type_from_diff_side(rule_diff.to),
                enforcement_type: enforcement)
            end

            rules_diff.updated.each do |rule_diff|
              emit_dependency_firewall_rule_event(action: 'update',
                rule_type: rule_type_from_diff_side(rule_diff.to),
                enforcement_type: enforcement)
            end

            rules_diff.deleted.each do |rule_diff|
              emit_dependency_firewall_rule_event(action: 'delete',
                rule_type: rule_type_from_diff_side(rule_diff.from),
                enforcement_type: enforcement)
            end
          end

          deleted_policies.each do |policy|
            content = policy.policy_content
            enforcement = content[:enforcement_type]
            Array.wrap(content[:rules]).each do |rule|
              emit_dependency_firewall_rule_event(action: 'delete',
                rule_type: rule[:type],
                enforcement_type: enforcement)
            end
          end
        end
      end

      def rule_type_from_diff_side(side)
        case side
        when Hash then side[:type] || side['type']
        else side.typed_content['type'] if side.respond_to?(:typed_content)
        end
      end

      def emit_dependency_firewall_rule_event(action:, rule_type:, enforcement_type:)
        value = DEPENDENCY_FIREWALL_ENFORCEMENT_VALUES[enforcement_type.to_s]
        return unless value
        return if rule_type.blank?

        track_internal_event(
          'dependency_firewall_policy_rule_changed',
          project: policy_configuration.project,
          namespace: policy_configuration.namespace,
          additional_properties: {
            label: action.to_s,
            property: rule_type.to_s,
            value: value
          }
        )
      end
    end
  end
end
