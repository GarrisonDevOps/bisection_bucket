# frozen_string_literal: true

module EE
  module MergeRequests
    module UpdateService
      include ::MergeRequests::ApprovalRulesAttributeMapping
      extend ::Gitlab::Utils::Override

      override :handle_changes
      def handle_changes(merge_request, options)
        saved_changes = merge_request.previous_changes.dup

        super

        reviewers_before = merge_request.reviewers.to_a
        handle_draft_state_change(merge_request, saved_changes)

        handle_reviewers_change(merge_request, reviewers_before) if merge_request.reviewers.to_a != reviewers_before

        handle_override_requested_changes(merge_request, saved_changes)
      end

      private

      override :general_fallback
      def general_fallback(merge_request)
        if merge_request.merged?
          params.delete(:reset_approval_rules_to_defaults)
          params.delete(:approval_rules_attributes)
        end

        reset_approval_rules(merge_request) if params.delete(:reset_approval_rules_to_defaults)

        merge_request = super(merge_request)

        merge_request.reset_approval_cache!

        return merge_request if update_task_event?

        ::MergeRequests::UpdateBlocksService
          .new(merge_request, current_user, blocking_merge_requests_params)
          .execute

        merge_request
      end

      override :after_update
      def after_update(merge_request, old_associations)
        super

        merge_request.run_after_commit do
          ::MergeRequests::SyncCodeOwnerApprovalRulesWorker.perform_async(merge_request.id)
        end

        event = ::MergeRequests::UpdatedEvent.new(data: { merge_request_id: merge_request.id })
        merge_request.run_after_commit_or_now do
          ::Gitlab::EventStore.publish(event)
        end
      end

      override :filter_approval_params
      def filter_approval_params(merge_request, current_user, params)
        return super unless update_v2_approval_rules?

        ::MergeRequests::V2ApprovalRules::ParamsFilteringService.new(merge_request, current_user, params).execute
      end

      override :delete_approvals_on_target_branch_change
      def delete_approvals_on_target_branch_change(merge_request)
        delete_approvals(merge_request) if reset_approvals?(merge_request, nil)
        schedule_policy_synchronization(merge_request)
        notify_for_policy_violations(merge_request)
        audit_security_policy_branch_bypass(merge_request)
      end

      override :filter_params
      def filter_params(merge_request)
        map_and_replace_approval_rules_attributes_to_v2 if update_v2_approval_rules?

        super
      end

      def reset_approval_rules(merge_request)
        return unless Ability.allowed?(current_user, :update_approvers, merge_request)

        merge_request.approval_rules.regular_or_any_approver.delete_all
      end

      def schedule_policy_synchronization(merge_request)
        merge_request.synchronize_approval_rules_from_target_project
        merge_request.schedule_policy_synchronization
      end

      def notify_for_policy_violations(merge_request)
        ::Security::SyncPolicyViolationCommentWorker.perform_async(merge_request.id)
      end

      def handle_override_requested_changes(merge_request, changed_fields)
        return unless changed_fields.include?('override_requested_changes')

        override_requested_changes = changed_fields['override_requested_changes']

        ::SystemNoteService.override_requested_changes(merge_request, current_user, override_requested_changes.last)
        audit_duo_requested_changes_override(merge_request) if override_requested_changes.last
        trigger_merge_request_status_updated(merge_request)

        ::Gitlab::EventStore.publish(
          ::MergeRequests::OverrideRequestedChangesStateEvent.new(
            data: { current_user_id: current_user.id, merge_request_id: merge_request.id }
          )
        )
      end

      def audit_duo_requested_changes_override(merge_request)
        return unless merge_request.change_requesters.duo_code_review_bot.exists?

        ::Gitlab::Audit::Auditor.audit(
          name: 'duo_code_review_requested_changes_overridden',
          author: current_user,
          scope: merge_request.target_project,
          target: merge_request,
          message: 'Overrode changes requested by GitLab Duo'
        )
      rescue StandardError => error
        # The override is already saved, so an audit failure must not fail the update.
        ::Gitlab::ErrorTracking.track_exception(error, merge_request_id: merge_request.id)
      end

      def should_publish_update_event?(merge_request, changed_fields)
        super || merge_request.has_jira_issue_keys?
      end

      def handle_draft_state_change(merge_request, changed_fields)
        return unless changed_fields.include?('title')

        old_title, new_title = changed_fields['title']

        return unless ::MergeRequest.draft?(old_title) && !::MergeRequest.draft?(new_title)

        assign_duo_as_reviewer_automatically(merge_request)
        assign_security_review_as_reviewer_automatically(merge_request)

        return unless merge_request.reviewer_auto_assignment_enabled?

        ::MergeRequests::AutoAssignReviewersWorker.perform_async(merge_request.id)
      end

      def update_v2_approval_rules?
        ::Feature.enabled?(:v2_approval_rules, project)
      end
    end
  end
end
