# frozen_string_literal: true

module MergeRequests
  class UpdateReviewerStateService < MergeRequests::BaseService
    # unapproved (revoking an approval) and the automatic review_started/unreviewed
    # transitions are excluded: they aren't a review the user is submitting.
    REVIEWER_ASSIGNMENT_STATES = %w[reviewed approved requested_changes].freeze

    # Duo Code Review passes `review_workflow_id` for a review session that it authorized.
    # It is a keyword argument, not a param, so request params cannot set it.
    # `fall_back_to_reviewed` records a refused review as `reviewed` and returns the reason as `warning`.
    def initialize(project:, current_user: nil, params: {}, review_workflow_id: nil, fall_back_to_reviewed: false)
      super(project: project, current_user: current_user, params: params)

      @review_workflow_id = review_workflow_id
      @fall_back_to_reviewed = fall_back_to_reviewed
    end

    def execute(merge_request, state)
      permission_error = review_state_permission_error(merge_request, state)
      return refuse_review_state(merge_request, state, permission_error) if permission_error

      # Capture reviewers before mutating so the webhook diff reflects a newly added reviewer.
      old_reviewers_hook_attrs = merge_request.reviewers_hook_attrs if submitted_review?(state)

      reviewer = resolve_reviewer(merge_request, state)

      create_requested_changes(merge_request) if state == 'requested_changes'
      destroy_requested_changes(merge_request) if state == 'approved'
      create_reviewed_system_note(merge_request) if state == 'reviewed'

      if reviewer
        return error("Reviewer has approved") if reviewer.approved? && %w[requested_changes unapproved].exclude?(state)
        return error("Failed to update reviewer") unless reviewer.update(state: state)

        trigger_merge_request_reviewers_updated(merge_request)
        trigger_user_merge_request_updated(merge_request)
        invalidate_cache_counts(merge_request, users: merge_request.assignees)
        current_user.invalidate_merge_request_cache_counts

        execute_submit_review_hooks(merge_request, state, old_reviewers_hook_attrs)

        return success(state: state) if state != 'requested_changes'

        if merge_request.approved_by?(current_user) && !remove_approval(merge_request, current_user)
          return error("Failed to remove approval")
        end

        publish_requested_changes_event(merge_request)

        success(state: state)
      else
        error("Reviewer not found")
      end
    end

    private

    attr_reader :review_workflow_id, :fall_back_to_reviewed

    def review_state_permission_error(merge_request, state)
      return error("Invalid permissions") unless can?(current_user, :create_merge_request_review, merge_request)

      # Approving and requesting changes decide whether the MR can merge, so both need approval rights.
      return if %w[approved requested_changes].exclude?(state)
      return if can?(current_user, :approve_merge_request, merge_request)

      error(_('You must be able to approve this merge request to request changes.'))
    end

    def refuse_review_state(merge_request, state, permission_error)
      return permission_error unless fall_back_to_reviewed && state == 'requested_changes'

      execute(merge_request, 'reviewed').merge(warning: permission_error[:message])
    end

    def publish_requested_changes_event(merge_request)
      return unless Gitlab::Ai::SoftwareFactory.enabled?(merge_request.project)

      Gitlab::EventStore.publish(
        MergeRequests::RequestedChangesCloudEvent.build(
          merge_request: merge_request,
          current_user: current_user,
          review_workflow_id: review_workflow_id
        )
      )
    end

    def create_requested_changes(merge_request)
      merge_request.create_requested_changes(current_user)

      SystemNoteService.requested_changes(merge_request, current_user)

      trigger_merge_request_merge_status_updated(merge_request)
    end

    def destroy_requested_changes(merge_request)
      merge_request.destroy_requested_changes(current_user)
    end

    def create_reviewed_system_note(merge_request)
      return if should_skip_review?

      SystemNoteService.reviewed(merge_request, current_user)
    end

    def should_skip_review?
      return false unless current_user.respond_to?(:user_type)

      current_user.duo_code_review_bot?
    end

    def execute_submit_review_hooks(merge_request, state, old_reviewers_hook_attrs)
      return unless submitted_review?(state)

      execute_hooks(
        merge_request,
        'update',
        old_associations: { reviewers_hook_attrs: old_reviewers_hook_attrs }
      )
    end

    def submitted_review?(state)
      # review_started and unreviewed are automatic transitions (a draft note is created or
      # destroyed, or reviewers are reset on push), not a review the user submitted.
      %w[review_started unreviewed].exclude?(state)
    end

    def resolve_reviewer(merge_request, state)
      if assign_reviewer_on_submission?(merge_request, state)
        merge_request.find_or_create_reviewer(current_user).tap do |reviewer|
          next unless reviewer&.previously_new_record?

          set_first_reviewer_assigned_at_metrics(merge_request)
          SystemNoteService.request_review(merge_request, merge_request.project, current_user, current_user, false)
        end
      else
        merge_request.find_reviewer(current_user)
      end
    end

    def assign_reviewer_on_submission?(merge_request, state)
      REVIEWER_ASSIGNMENT_STATES.include?(state) &&
        !should_skip_review? &&
        merge_request.author_id != current_user.id &&
        can_add_reviewer?(merge_request)
    end

    # find_or_create_reviewer writes the row directly, bypassing the reviewer-count
    # validation, so the limit is enforced here. Not atomic with the create, so concurrent
    # submissions can briefly exceed it, which is acceptable for this best-effort assignment.
    def can_add_reviewer?(merge_request)
      if merge_request.allows_multiple_reviewers?
        merge_request.reviewers.size < Issuable::MAX_NUMBER_OF_ASSIGNEES_OR_REVIEWERS
      else
        merge_request.reviewers.empty?
      end
    end
  end
end
