# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class ProtectedBranchesDeletionCheckService < BaseProjectService
      include Gitlab::Utils::StrongMemoize
      include Concerns::ProtectedBranchesDeletionCheck

      def initialize(project:, current_user: nil, ignore_warn_mode: false)
        super(project: project, current_user: current_user)
        @ignore_warn_mode = ignore_warn_mode
      end

      def execute(protected_branches)
        protected_branches.reject do |protected_branch|
          applicable_branches.none? do |branch|
            RefMatcher.new(branch).matching([protected_branch.name]).any?
          end
        end
      end

      private

      attr_reader :ignore_warn_mode

      def applicable_branches
        PolicyBranchesService.new(project: project).scan_result_branches(rules).merge(blocked_branch_patterns)
      end
      strong_memoize_attr :applicable_branches

      def blocked_branch_patterns
        rules.filter_map { |rule| rule[:branches] }.flatten
      end

      def rules
        blocking_policies
          .flat_map(&:undeleted_approval_policy_rules)
          .map(&:typed_content)
          .map(&:deep_symbolize_keys)
      end
      strong_memoize_attr :rules

      def blocking_policies
        project
          .security_policies
          .type_approval_policy
          .enabled
          .preload_approval_policy_rules
          .select { |policy| policy_applicable?(policy) }
      end
      strong_memoize_attr :blocking_policies

      def policy_applicable?(policy)
        return false unless approval_settings_block_modification?(policy)
        return false if warn_mode_policy?(policy) && !ignore_warn_mode
        return false if bot_can_bypass_policy?(policy)

        true
      end

      def approval_settings_block_modification?(policy)
        policy.approval_policy&.approval_settings&.block_branch_modification == true
      end
    end
  end
end
