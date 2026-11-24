# frozen_string_literal: true

module MergeRequests
  class ResetApprovalsService < ::MergeRequests::BaseService
    def execute(ref, newrev, skip_reset_checks: false, oldrev: nil)
      @oldrev = oldrev

      reset_approvals_for_merge_requests(ref, newrev, skip_reset_checks)
    end

    private

    def reset_approvals_for_merge_requests(ref, newrev, skip_reset_checks = false)
      branch_name = ::Gitlab::Git.ref_name(ref)

      merge_requests = merge_requests_for_approval_reset(branch_name)

      preload_for_approval_reset(merge_requests)

      merge_requests.each do |merge_request|
        mr_patch_id_sha = merge_request.current_patch_id_sha

        if skip_reset_checks
          # Delete approvals immediately, with no additional checks or side-effects
          #
          delete_approvals(merge_request, patch_id_sha: mr_patch_id_sha, cause: :new_push)
        else
          reset_approvals(merge_request, newrev, patch_id_sha: mr_patch_id_sha)
        end

        merge_request.approval_state.expire_unapproved_key!
        trigger_merge_request_merge_status_updated(merge_request)
        AutoMergeProcessWorker.perform_async(merge_request.id) if merge_request.auto_merge_enabled?
      end
    end

    def reset_approvals(merge_request, newrev = nil, patch_id_sha: nil, cause: :new_push)
      return unless reset_approvals?(merge_request, newrev)

      if delete_approvals?(merge_request)
        delete_approvals(merge_request, patch_id_sha: patch_id_sha, cause: cause)
      elsif merge_request.target_project.project_setting.selective_code_owner_removals ||
          selective_code_owner_removals_from_policy?(merge_request)
        delete_code_owner_approvals(merge_request, patch_id_sha: patch_id_sha, cause: cause)
      end
    end

    def delete_code_owner_approvals(merge_request, patch_id_sha: nil, cause: nil)
      return if merge_request.approvals.empty?

      # Batch execution preloads approvals; retain loading for direct calls.
      merge_request.approvals.load

      code_owner_rules = approved_code_owner_rules(merge_request)
      return if code_owner_rules.empty?

      # Only do expensive approver ID extraction if we have code owner rules to check
      approver_ids = code_owner_approver_ids_to_delete(merge_request, code_owner_rules, patch_id_sha)
      return if approver_ids.empty?

      perform_code_owner_approval_deletion(merge_request, approver_ids, cause)
    end

    def approved_code_owner_rules(merge_request)
      merge_request.wrapped_approval_rules.select { |rule| rule.code_owner? && rule.approved_approvers.any? }
    end

    def code_owner_approver_ids_to_delete(merge_request, code_owner_rules, patch_id_sha)
      previous_diff_head_sha = resolve_previous_diff_head_sha(merge_request)

      rule_names = ::Gitlab::CodeOwners.entries_since_merge_request_commit(merge_request,
        sha: previous_diff_head_sha).map(&:pattern)
      return [] if rule_names.empty?

      match_ids = code_owner_rules.flat_map do |rule|
        next unless rule_names.include?(rule.name)

        rule.approved_approvers.map(&:id)
      end.compact
      return [] if match_ids.empty?

      filtered_approvals = merge_request.approvals.where(user_id: match_ids) # rubocop:disable CodeReuse/ActiveRecord
      filtered_approvals = filter_approvals(filtered_approvals, patch_id_sha) if patch_id_sha.present?
      filtered_approvals.map(&:user_id)
    end

    def perform_code_owner_approval_deletion(merge_request, approver_ids, cause)
      # Check if merge request is approved BEFORE deleting any approvals
      # We need to clear the approval state cache to get the current state
      reset_approval_cache!(merge_request)
      was_approved = merge_request.approval_state.all_approval_rules_approved?

      filtered_approvals = merge_request.approvals.where(user_id: approver_ids) # rubocop:disable CodeReuse/ActiveRecord
      filtered_approvals.delete_all

      # In case there is still a temporary flag on the MR
      merge_request.approval_state.expire_unapproved_key!

      merge_request.batch_update_reviewer_state(approver_ids, 'unapproved')

      trigger_merge_request_merge_status_updated(merge_request)
      trigger_merge_request_approval_state_updated(merge_request)
      publish_approvals_reset_event(merge_request, cause, approver_ids)

      trigger_code_owner_webhook_events(merge_request, was_approved, cause)
    end

    def trigger_code_owner_webhook_events(merge_request, was_approved, cause)
      # Trigger webhook events for system-initiated approval resets
      return unless cause == :new_push

      # Check approval state AFTER deletion to determine correct webhook event
      # Clear memoization again to ensure we get the updated state after deletion
      reset_approval_cache!(merge_request)
      is_currently_approved = merge_request.approval_state.all_approval_rules_approved?

      # Only send 'unapproved' if the MR transitioned from approved to not approved
      if was_approved && !is_currently_approved
        execute_hooks(merge_request, 'unapproved', system: true, system_action: 'code_owner_approvals_reset_on_push')
      else
        # Send 'unapproval' for individual approval removal that doesn't change overall approval state
        execute_hooks(merge_request, 'unapproval', system: true, system_action: 'code_owner_approvals_reset_on_push')
      end
    end

    def reset_approval_cache!(merge_request)
      merge_request.approvals.reset
      merge_request.approved_by_users.reset
      merge_request.clear_memoization(:approval_state)

      merge_request.delete_approval_mergeability_cache
    end

    def preload_for_approval_reset(merge_requests)
      return if merge_requests.empty?

      # Always needed: current_patch_id_sha, reset_approvals?/delete_approvals? checks
      ActiveRecord::Associations::Preloader.new(
        records: merge_requests,
        associations: [
          :merge_request_diff,
          :approvals,
          :scan_result_policy_violations,
          :security_policies_through_violations,
          { target_project: :project_setting }
        ]
      ).call

      # Only needed for the selective code owner removal path
      return unless project.project_setting.selective_code_owner_removals ||
        merge_requests.any? { |merge_request| selective_code_owner_removals_from_policy?(merge_request) }

      ActiveRecord::Associations::Preloader.new(
        records: merge_requests,
        associations: [
          :approval_rules,
          :merge_request_diffs,
          { target_project: :regular_or_any_approver_approval_rules }
        ]
      ).call
    end

    def resolve_previous_diff_head_sha(merge_request)
      if @oldrev
        if merge_request.merge_request_diffs.exists?(head_commit_sha: @oldrev) # rubocop:disable CodeReuse/ActiveRecord -- simple existence check on association
          return @oldrev
        end

        Gitlab::AppLogger.warn(
          message: 'oldrev does not match any merge request diff head_commit_sha, falling back to previous_diff',
          merge_request_id: merge_request.id,
          oldrev: @oldrev
        )
      end

      merge_request.previous_diff&.head_commit_sha
    end
  end
end
