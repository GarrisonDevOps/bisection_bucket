# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class UpdateSecurityPoliciesService
      def initialize(policies_changes:)
        @policies_changes = policies_changes
      end

      def execute
        policies_changes.each_with_object([]) do |policy_changes, updated_policies|
          # diff should be computed before updating policy attributes
          diff = policy_changes.diff
          policy = update_policy_attributes!(policy_changes.db_policy, policy_changes.yaml_policy)

          update_policy_rules(policy, diff.rules_diff)
          policy.update_pipeline_execution_policy_config_link! if policy_changes.diff.content_project_changed?

          updated_policies << policy
        end
      end

      private

      attr_reader :policies_changes

      def update_policy_attributes!(db_policy, yaml_policy)
        db_policy.update!(
          Security::Policy.attributes_from_policy_hash(db_policy.type.to_sym, yaml_policy,
            db_policy.security_orchestration_policy_configuration)
        )
        db_policy
      end

      def update_policy_rules(policy, rules_diff)
        return unless rules_diff

        mark_rules_for_deletion(policy, rules_diff.deleted)
        update_existing_rules(policy, rules_diff.updated)
        create_new_rules(policy, rules_diff.created)
      end

      def update_existing_rules(policy, updated_rules)
        updated_rules.each do |rule_diff|
          rule_record = rule_diff.from
          policy.upsert_rule(rule_record.rule_index, rule_diff.to)
        end
      end

      def create_new_rules(policy, created_rules)
        new_index = policy.next_rule_index
        created_rules.each_with_index do |rule_diff, index|
          rule_hash = rule_diff.to
          rule = policy.upsert_rule(new_index + index, rule_hash)
          rule_diff.id = rule.id if rule
        end
      end

      def mark_rules_for_deletion(policy, deleted_rules)
        # Start past the current maximum so we never reuse an index still held by a
        # rule tombstoned in an earlier run.
        new_index = policy.max_rule_index + 1
        deleted_rules.each_with_index do |rule_diff, index|
          rule_record = rule_diff.from
          rule_record.update!(rule_index: -(new_index + index))
        end
      end
    end
  end
end
