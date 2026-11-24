# frozen_string_literal: true

module MergeRequests
  module Refresh
    class ApprovalService < ::MergeRequests::Refresh::BaseService
      extend ::Gitlab::Utils::Override

      attr_reader :push

      def execute(oldrev, newrev, ref)
        @push = Gitlab::Git::Push.new(@project, oldrev, newrev, ref)
        return true unless @push.branch_push?

        update_approvers_for_source_branch_merge_requests
        update_approvers_for_target_branch_merge_requests
        reset_approvals_for_merge_requests(push.ref, push.newrev)
        sync_any_merge_request_approval_rules
        sync_preexisting_states_approval_rules
        sync_unenforceable_approval_rules
      end

      private

      def update_approvers_for_source_branch_merge_requests
        merge_requests_for_source_branch.each do |merge_request|
          if project.licensed_feature_available?(:code_owners)
            ::MergeRequests::SyncCodeOwnerApprovalRules.new(merge_request).execute
          end

          ::MergeRequests::SyncReportApproverApprovalRules.new(merge_request, current_user).execute
        end
      end

      def reset_approvals_for_merge_requests(ref, newrev)
        # Flag MRs as temporarily unapproved to prevent merging while the
        # async approval reset is in progress. Use the short reset TTL: this
        # only bridges the ~10s until MergeRequestResetApprovalsWorker runs, and
        # code owner rules are already synced synchronously above, so this flag
        # is not the code owner race guard (that is the create flow's longer
        # TTL). A short TTL avoids leaving a flagged-but-not-reset MR (e.g. one
        # with no approvals) stuck in `checking` for the full 5 minutes.
        merge_requests_for(push.branch_name, mr_states: [:opened]).each do |mr|
          next unless reset_approvals?(mr, newrev)

          mr.approval_state.temporarily_unapprove!(ApprovalState::TEMPORARILY_UNAPPROVED_TTL_ON_RESET)
        end

        # We need to make sure the code owner approval rules have all been synced
        #   first, so we delay for 10s. We are trying to pin down and fix the race
        #   condition: https://gitlab.com/gitlab-org/gitlab/-/issues/373846
        MergeRequestResetApprovalsWorker.perform_in(10.seconds, project.id, current_user.id, ref, newrev, push.oldrev)
      end

      def update_approvers_for_target_branch_merge_requests
        return unless project.licensed_feature_available?(:code_owners) && branch_protected? && code_owners_updated?

        merge_requests_for_target_branch.each do |merge_request|
          ::MergeRequests::SyncCodeOwnerApprovalRules.new(merge_request).execute unless merge_request.on_train?
        end
      end

      def sync_any_merge_request_approval_rules
        # The service's `@project` is the pushed-to project - the fork for fork
        # merge requests - but policies are enforced by each merge request's
        # target project.
        merge_requests_for_source_branch.each do |merge_request|
          next unless approval_policy_rules_targeting_commits?(merge_request.target_project)

          ::Security::ScanResultPolicies::SyncAnyMergeRequestApprovalRulesWorker.perform_async(merge_request.id)
        end
      end

      def approval_policy_rules_targeting_commits?(target_project)
        strong_memoize_with(:approval_policy_rules_targeting_commits, target_project.id) do
          target_project.approval_policy_rules_targeting_commits?
        end
      end

      def sync_preexisting_states_approval_rules
        merge_requests_for_source_branch.each do |merge_request|
          if merge_request.approval_rules.by_report_types([:scan_finding, :license_scanning]).any?
            ::Security::ScanResultPolicies::SyncPreexistingStatesApprovalRulesWorker.perform_async(merge_request.id)
          end
        end
      end

      def sync_unenforceable_approval_rules
        merge_requests = merge_requests_for_source_branch

        preload_head_pipeline_for_merge_requests(merge_requests)

        merge_requests.each do |merge_request|
          if merge_request.diff_head_pipeline.blank?
            ::Security::UnenforceablePolicyRulesNotificationWorker.perform_async(merge_request.id)
          end
        end
      end

      override :merge_requests_for
      # rubocop: disable CodeReuse/ActiveRecord -- mirrors base class merge_requests_for with additional preloads
      def merge_requests_for(source_branch, mr_states: [:opened])
        @project.source_of_merge_requests
          .with_state(mr_states)
          .where(source_branch: source_branch)
          .preload(:source_project, :target_project, :latest_merge_request_diff, :merge_head_diff, :merge_train_car)
          .select(&:source_project)
      end
      # rubocop: enable CodeReuse/ActiveRecord

      def branch_protected?
        project.branch_requires_code_owner_approval?(push.branch_name)
      end

      def preload_head_pipeline_for_merge_requests(merge_requests)
        ActiveRecord::Associations::Preloader.new(
          records: merge_requests,
          associations: %i[head_pipeline merge_request_diff]
        ).call
      end

      def merge_requests_for_target_branch
        @target_merge_requests ||= project.merge_requests
          .with_state([:opened])
          .by_target_branch(push.branch_name)
          .including_merge_train
      end

      def code_owners_updated?
        return unless push.branch_updated?

        push.modified_paths.find { |path| ::Gitlab::CodeOwners::FILE_PATHS.include?(path) }
      end

      override :reset_approvals?
      def reset_approvals?(merge_request, newrev)
        !merge_request.merge_train_car && super
      end
    end
  end
end
