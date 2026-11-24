# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    module Concerns
      module ProtectedBranchesDeletionCheck
        private

        def bot_can_bypass_policy?(policy)
          return false unless current_user

          bypass_checker = Security::ScanResultPolicies::BotBypassChecker.new(
            bypass_settings: policy.approval_policy.bypass_settings,
            user: current_user
          )

          return false unless bypass_checker.bypass_allowed?

          log_bypass_audit(policy, bypass_checker)
          true
        end

        def log_bypass_audit(policy, bypass_checker)
          return unless container

          auditor = Security::ScanResultPolicies::BranchDeletionBypassAuditor.new(
            security_policy: policy,
            container: container,
            user: current_user
          )

          if bypass_checker.service_account_id
            auditor.log_service_account_bypass(bypass_checker.service_account_id)
          elsif bypass_checker.access_token_ids
            auditor.log_access_token_bypass(bypass_checker.access_token_ids)
          end
        end

        def warn_mode_policy?(policy)
          policy.enforcement_type_warn?
        end
      end
    end
  end
end
