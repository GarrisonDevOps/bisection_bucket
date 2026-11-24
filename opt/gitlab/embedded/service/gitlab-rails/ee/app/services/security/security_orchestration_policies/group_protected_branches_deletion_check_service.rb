# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class GroupProtectedBranchesDeletionCheckService < BaseGroupService
      include Concerns::ProtectedBranchesDeletionCheck

      BlockingPolicy = Data.define(:policy_configuration_id, :security_policy_name)

      def initialize(group:, current_user: nil, params: {}, ignore_warn_mode: false)
        super(group: group, current_user: current_user)
        @params = params
        @ignore_warn_mode = ignore_warn_mode
      end

      def execute
        all_configurations = group.all_security_orchestration_policy_configurations

        configuration_ids = all_configurations.map(&:id)
        policies = Security::Policy
          .for_policy_configuration_ids(configuration_ids)
          .preload_approval_policy_rules
          .type_approval_policy
          .enabled

        policies.each do |policy|
          next unless applies?(policy)

          return true unless collect_blocking_policies?

          blocking_policies << BlockingPolicy.new(policy.security_orchestration_policy_configuration_id, policy.name)
        end

        blocking_policies.any?
      end

      def blocking_policies
        @blocking_policies ||= []
      end

      private

      attr_reader :ignore_warn_mode, :params

      def collect_blocking_policies?
        params[:collect_blocking_policies]
      end

      def warn_mode_policies_only?
        params[:policy_enforcement_type] == ::Security::Policy::ENFORCEMENT_TYPE_WARN
      end

      def applies?(policy)
        return false unless policy_applicable_by_approval_settings?(policy)
        return false unless policy_applicable_by_enforcement?(policy)

        true
      end

      def policy_applicable_by_approval_settings?(policy)
        approval_settings = policy.approval_policy&.approval_settings
        return false unless approval_settings

        return true if blocks_all_branch_modification?(approval_settings)

        return false unless approval_settings.block_group_branch_modification_enabled?

        exception_ids = approval_settings.block_group_branch_modification_exception_group_ids
        exception_ids.blank? || exception_ids.exclude?(group.id)
      end

      def policy_applicable_by_enforcement?(policy)
        config = policy.security_orchestration_policy_configuration

        if warn_mode_policies_only?
          return false unless config && !ignore_warn_mode

          warn_mode_policy?(policy)
        else
          policy_in_block_mode?(policy) && !bot_can_bypass_policy?(policy)
        end
      end

      def policy_in_block_mode?(policy)
        ignore_warn_mode || !warn_mode_policy?(policy)
      end

      def blocks_all_branch_modification?(approval_settings)
        approval_settings.block_branch_modification && approval_settings.block_group_branch_modification.nil?
      end
    end
  end
end
