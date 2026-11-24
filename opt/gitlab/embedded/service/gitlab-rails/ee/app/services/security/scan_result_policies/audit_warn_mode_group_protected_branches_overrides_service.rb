# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class AuditWarnModeGroupProtectedBranchesOverridesService < BaseGroupService
      AUDIT_EVENT = 'policy_warn_mode_group_protected_branch_modification_override'

      def execute
        return if enforced_policies_block_modification? || !warn_mode_policies_block_modification?

        ensure_policy_bots_exist!

        ::Gitlab::Audit::Auditor.audit(initial_audit_context) do
          blocking_warn_mode_policies.each do |policy|
            policy_project = policy.security_policy_management_project

            event = {
              message: message(policy),
              target: policy,
              scope: policy_project,
              author: policy_project.security_policy_bot
            }

            policy.push_audit_event(event, after_commit: false)
          end
        end
      end

      private

      def ensure_policy_bots_exist!
        blocking_warn_mode_policies.each do |policy|
          policy_project = policy.security_policy_management_project

          next if policy_project.security_policy_bot

          Security::Orchestration::CreateBotService.new(policy_project, nil, skip_authorization: true).execute.user
        end
      end

      def blocking_warn_mode_policies
        tuples = warn_mode_check_service.blocking_policies.map do |blocking_policy|
          [blocking_policy.policy_configuration_id, blocking_policy.security_policy_name]
        end

        Security::Policy
          .for_configuration_id_and_name_tuples(tuples)
          .type_approval_policy
          .including_security_policy_management_project
      end
      strong_memoize_attr :blocking_warn_mode_policies

      def initial_audit_context
        {
          name: AUDIT_EVENT,
          # We need to set `author`, `target` and `scope` for feature availability checks.
          # We override them when we push the individual audit events.
          author: group.owner,
          scope: group,
          target: group
        }
      end

      def message(policy)
        "The group #{group.full_path} is affected by the warn mode policy #{policy.name} " \
          "that prevents modification of the group's protected branches " \
          "if the policy changes from warn mode to enforced."
      end

      def enforced_policies_block_modification?
        Security::SecurityOrchestrationPolicies::GroupProtectedBranchesDeletionCheckService
          .new(group: group)
          .execute
      end

      def warn_mode_policies_block_modification?
        warn_mode_check_service.execute
      end

      def warn_mode_check_service
        @warn_mode_check_service ||= Security::SecurityOrchestrationPolicies::GroupProtectedBranchesDeletionCheckService
                                         .new(
                                           group: group,
                                           params: { policy_enforcement_type: ::Security::Policy::ENFORCEMENT_TYPE_WARN,
                                                     collect_blocking_policies: true })
      end
    end
  end
end
