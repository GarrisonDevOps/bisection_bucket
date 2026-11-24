# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class PushSettingsOverrides
      include Gitlab::Utils::StrongMemoize

      Override = Data.define(:security_policy, :attribute, :protected_branches)

      def initialize(project:, warn_mode_policies:)
        @project = project
        @warn_mode_policies = warn_mode_policies
      end

      def all
        warn_mode_policies.each_with_object([]) do |policy, overrides|
          applicable_branches = applicable_protected_branches_by_policy(policy)

          if approval_setting_enabled?(policy, "block_branch_modification")
            add_block_modification_override(policy, applicable_branches, overrides)
          end

          if approval_setting_enabled?(policy, "prevent_pushing_and_force_pushing")
            add_prevent_push_override(policy, applicable_branches, overrides)
          end
        end
      end

      private

      attr_reader :project, :warn_mode_policies

      def add_block_modification_override(policy, applicable_branches, overrides)
        allowed_branches = applicable_branches.reject(&:modification_blocked_by_policy?)
        return if allowed_branches.empty?

        overrides << Override.new(policy, :block_branch_modification, allowed_branches)
      end

      def add_prevent_push_override(policy, applicable_branches, overrides)
        push_allowed_branches = applicable_branches.select(&:allow_force_push?)
        return if push_allowed_branches.empty?

        overrides << Override.new(policy, :prevent_pushing_and_force_pushing, push_allowed_branches)
      end

      def applicable_protected_branches_by_policy(policy)
        rules = approval_policy_rules(policy)

        applicable_branches_by_rules(rules).flat_map do |affected_branch|
          ProtectedBranch.matching(affected_branch, protected_refs: project.protected_branches)
        end.uniq(&:id)
      end

      def approval_policy_rules(policy)
        # rubocop:disable CodeReuse/ActiveRecord -- doesn't belong in model
        policy.approval_policy_rules.pluck(:content).map(&:deep_symbolize_keys)
        # rubocop:enable CodeReuse/ActiveRecord
      end

      def applicable_branches_by_rules(rules)
        Security::SecurityOrchestrationPolicies::PolicyBranchesService
          .new(project: project)
          .scan_result_branches(rules)
      end

      def approval_setting_enabled?(policy, attribute)
        !!policy.content.dig("approval_settings", attribute)
      end
    end
  end
end
