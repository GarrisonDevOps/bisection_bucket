# frozen_string_literal: true

module EE
  module Gitlab
    module Checks
      module Security
        module PolicyCheck
          PUSH_ERROR_MESSAGE = "Push is blocked by settings overridden by a security policy"
          FORCE_PUSH_ERROR_MESSAGE = "Force push is blocked by settings overridden by a security policy"
          BYPASS_REASON_ERROR_MESSAGE = "Bypass reason is required when bypassing security policy restrictions"
          LOG_MESSAGE = "Checking if scan result policies apply to branch..."

          def validate!
            return unless project.licensed_feature_available?(:security_orchestration_policies)

            logger.log_timed(LOG_MESSAGE) do
              break unless branch_name_affected_by_policy?
              break if policies_bypass_applied?
              # Defer to Gitlab::Checks::BranchCheck for branch creation. The standard
              # layer already enforces "Allowed to merge" and safe-commit checks for new
              # protected branches; double-blocking here creates a deadlock for
              # Maintainers seeding branches in projects covered by a group-level policy.
              # See https://gitlab.com/gitlab-org/gitlab/-/work_items/597395.
              break if creation?

              if force_push?
                raise ::Gitlab::GitAccess::ForbiddenError, FORCE_PUSH_ERROR_MESSAGE
              elsif !matching_merge_request?
                raise ::Gitlab::GitAccess::ForbiddenError, PUSH_ERROR_MESSAGE
              end
            end
          end

          private

          def branch_name_affected_by_policy?
            affected_branches = ::Security::SecurityOrchestrationPolicies::ProtectedBranchesPushService
              .new(project: project).execute

            branch_name.in? affected_branches
          end

          def policies_bypass_applied?
            bypass = change_access.security_policy_bypass

            if bypass.bypass_reason_required?
              raise ::Gitlab::GitAccess::ForbiddenError, BYPASS_REASON_ERROR_MESSAGE unless matching_merge_request?

              return false
            end

            bypass.policy_bypass_granted?
          end

          def force_push?
            ::Gitlab::Checks::ForcePush.force_push?(project, oldrev, newrev)
          end

          def matching_merge_request?
            ::Gitlab::Checks::MatchingMergeRequest.new(newrev, branch_name, project).match?
          end
        end
      end
    end
  end
end
