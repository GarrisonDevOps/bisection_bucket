# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Variables
        module Preloader
          module MergeRequest
            extend ::Gitlab::Utils::Override

            # the `approved?` method when assigning `CI_MERGE_REQUEST_APPROVED`
            APPROVED_PRELOADS = [
              :approvals,
              :approved_by_users,
              {
                applicable_post_merge_approval_rules: [
                  :approved_approvers,
                  :group_users, :users,
                  { approval_project_rule: [:protected_branches, :group_users, :users] }
                ],
                approval_rules: [
                  :group_users, :users,
                  { approval_project_rule: [:protected_branches, :group_users, :users] }
                ],
                target_project: [
                  regular_or_any_approver_approval_rules: [:protected_branches, :group_users, :users]
                ]
              },
              :scan_result_policy_violations,
              :scan_result_policy_reads_through_violations,
              :running_scan_result_policy_violations,
              :scan_result_policy_reads_through_approval_rules
            ].freeze

            private

            override :preloads
            def preloads
              result = super + APPROVED_PRELOADS
              result += committer_approval_preloads if preload_committer_approvals?
              result
            end

            def preload_committer_approvals?
              merge_request.merge_requests_disable_committers_approval?
            end

            def committer_approval_preloads
              commit_preloads = [{ merge_request_commits_metadata: [:commit_author, :committer] }]

              unless ::MergeRequestDiffCommit.read_new_commits_table?(merge_request.target_project_id)
                commit_preloads += [:commit_author, :committer]
              end

              [{ merge_request_diff: [{ merge_request_diff_commits: commit_preloads }] }]
            end
          end
        end
      end
    end
  end
end
