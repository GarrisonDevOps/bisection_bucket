# frozen_string_literal: true

module MergeTrains
  class RefreshMergeRequestService < BaseService
    include Gitlab::Utils::StrongMemoize

    ProcessError = Class.new(StandardError)
    ConcurrencyError = Class.new(StandardError)
    UnlockError = Class.new(StandardError)
    ReconcileError = Class.new(StandardError)

    attr_reader :merge_request

    ##
    # Arguments:
    # merge_request ... The merge request to be refreshed
    def execute(merge_request)
      @merge_request = merge_request

      # Unstick mechanism for stuck merge requests
      if merge_train_car.merging?
        if timed_out?
          unstick!
        else
          raise ConcurrencyError, 'concurrency error'
        end
      else
        validate!
        pipeline_created = create_pipeline! if merge_train_car.requires_new_pipeline? || require_recreate?

        log_running_security_scans

        merge! if merge_train_car.merge_ready_pipeline?
        success(pipeline_created: pipeline_created.present?)
      end
    rescue ProcessError => e
      abort(e)
    rescue ConcurrencyError, ReconcileError
      # We're not going to abort here, but we want the worker to crash to be picked up again.
      # We don't want the car to get destroyed but rather unlocked, when the worker gets picked up again, if we run into the given timeout,
      # or an mr could not be unlocked (which should never happen).
      # ReconcileError also covers a transient silently-merged fixup.
      raise
    rescue UnlockError => e
      abort(e)
      merge_request.add_to_locked_set
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(
        e,
        merge_request_id: merge_request.id,
        merge_request_iid: merge_request.iid,
        project_id: merge_request.target_project_id
      )

      abort(
        ProcessError.new(
          "an unexpected error occurred. Correlation ID: #{Labkit::Correlation::CorrelationId.current_or_new_id}."
        )
      )
    end

    private

    def handle_silently_merged_stuck_car
      finalize_silently_merged_merge!
      log_unstick_action('reconciled_silently_merged')
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(
        e,
        merge_request_id: merge_request.id,
        merge_request_iid: merge_request.iid,
        project_id: merge_request.target_project_id,
        handler: 'handle_silently_merged_stuck_car'
      )

      merge_request.reset

      # PostMergeService marks the MR merged as its first step, so a later failure
      # leaves it merged. handle_locked_stuck_car would then unlock_mr (invalid on a
      # merged MR) and abort, losing the car. Finish it instead; never abort a merge.
      if merge_request.merged?
        finish_already_merged_car
        log_unstick_action('reconciled_silently_merged')
        return
      end

      handle_locked_stuck_car
    end

    def validate!
      unless project.merge_trains_enabled?
        raise ProcessError, 'merge trains are disabled for this project.'
      end

      unless merge_request.on_train?
        raise ProcessError, 'the merge request is not on a merge train.'
      end

      validate_merge_request!

      unless merge_train_car.previous_ref_sha.present?
        raise ProcessError, "the previous ref does not exist. [Learn more](#{learn_more_url})."
      end

      if merge_train_car.pipeline_not_succeeded?
        raise ProcessError, "the pipeline did not succeed. [Learn more](#{learn_more_url})."
      end
    end

    def unstick!
      if merge_request.merged_in_repository? && (merge_request.locked? || merge_request.opened?)
        handle_silently_merged_stuck_car
      elsif merge_request.merged?
        handle_merged_stuck_car
      elsif merge_request.locked?
        handle_locked_stuck_car
      elsif merge_request.open?
        handle_open_stuck_car
      elsif merge_request.closed?
        handle_closed_stuck_car
      else
        # Should be unreachable. Defensive guard against future changes
        handle_unexpected_merge_request_state
      end

      success(pipeline_created: false)
    end

    # This should never be called.
    # If this happens nevertheless, something has changed with the state machine of the merge request e.g.
    # a new state has been added.
    def handle_unexpected_merge_request_state
      Gitlab::ErrorTracking.track_exception(
        StandardError.new("Unexpected merge request state during unstick: #{merge_request.state}"),
        merge_request_id: merge_request.id,
        merge_request_iid: merge_request.iid,
        project_id: merge_request.target_project_id,
        merge_request_state: merge_request.state
      )

      raise ProcessError, "the merge did not complete in time. [Learn more](#{learn_more_url})."
    end

    def handle_merged_stuck_car
      merge_train_car.finish_merge!
      log_unstick_action('finish_merge')
    end

    def handle_locked_stuck_car
      if merge_request.unlock_mr
        log_unstick_action('abort_merge_locked')
        raise ProcessError, "the merge did not complete in time. [Learn more](#{learn_more_url})."
      else
        # In very special, seldom cases, we cannot unlock a stuck MR due to validation errors.
        # In that cases, we destroy the car and hand over to the already existing unlock service.
        log_unstick_action('forced_unlock', merge_request.errors.full_messages)
        raise UnlockError, "the merge did not complete in time. [Learn more](#{learn_more_url})."
      end
    end

    def handle_open_stuck_car
      log_unstick_action('abort_merge_open')
      raise ProcessError, "the merge did not complete in time. [Learn more](#{learn_more_url})."
    end

    def handle_closed_stuck_car
      if merge_train_car.destroy
        log_unstick_action('destroy_closed')
      else
        log_unstick_action('destroy_failed')
      end
    end

    def timed_out?
      merge_train_car.updated_at < MergeTrains::Car::STUCK_AFTER.ago
    end

    def log_unstick_action(action, errors = nil)
      Gitlab::AppLogger.warn(
        message: 'Unstuck stuck merge train merge',
        action: action,
        merge_request_id: merge_request.id,
        merge_request_iid: merge_request.iid,
        project_id: merge_request.target_project_id,
        errors: errors
      )
    end

    def validate_merge_request!
      unless merge_request.open?
        raise ProcessError, "the merge request is closed. [Learn more](#{learn_more_url})."
      end

      if merge_request.broken?
        raise ProcessError, "the merge request is broken. [Learn more](#{learn_more_url})."
      end

      if merge_request.draft?
        raise ProcessError, "the merge request is marked as draft. [Learn more](#{learn_more_url})."
      end

      unless merge_request.auto_merge_enabled?
        raise ProcessError, 'the merge request is not set to auto-merge.'
      end
    end

    def learn_more_url
      Rails.application.routes.url_helpers.help_page_url(
        'ci/pipelines/merge_trains.md',
        anchor: 'merge-request-dropped-from-the-merge-train'
      )
    end

    # Messages here range from our own validation strings to raw Gitaly errors that
    # carry a gRPC status code and hide the real conflict, so normalise and frame them.
    # See https://gitlab.com/gitlab-org/gitaly/-/work_items/7330.
    def pipeline_creation_error(message)
      detail = message.to_s.sub(/\A\d+:\s*/, '').chomp('.')

      "the merge train pipeline could not be prepared: #{detail}. [Learn more](#{learn_more_url})."
    end

    def merge_from_train_ref?
      unless project.ff_merge_must_be_possible? ||
          Feature.enabled?(:merge_trains_use_train_ref_for_standard_merges, project)
        return false
      end

      # The FromTrainRef strategy does not yet support restartless merges
      # (skip_merged). A skip-merge changes the target branch, making the
      # train ref no longer a valid fast-forward candidate.
      return false if project.merge_trains_skip_train_allowed?

      mergeable_sha_and_message?(merge_train_car)
    end

    def create_mergeable_train_ref?
      # The two checks below ensure that by construction, we can safely
      # fast-forward merge from any train ref satisfying
      # #mergeable_from_train_ref?
      #
      # (1) Base case: If we're the first car, then the train ref will be based
      # on the target branch, and is trivially mergeable. We use #prev instead
      # of #first_active_car? to guard against an unlikely edge case where the car
      # becomes the first car in between those two checks.
      prev = merge_train_car.prev_active
      return true if prev.nil?

      # (2) Recursive case: The previous MR has not been merged, so we check
      # whether it was constructed with a mergeable train ref.
      mergeable_sha_and_message?(prev)
    end

    def mergeable_sha_and_message?(car)
      # The commit message check guards against a very unlikely edge case in
      # which a merge train created by MergeTrains::CreateRefService has been
      # running since before standard merge commits were first enabled, and no
      # merge has occurred.
      #
      # The train_ref commit_sha check is for mixed rollout scenarios, such as
      # when the various feature flags are toggled, or when old code is running
      # concurrently with new code, or when a train exists from before the
      # instance was updated.
      sha = car.pipeline&.sha
      project.commit(sha)&.message != MergeTrains::MergeCommitMessage.legacy_value(merge_request, car.previous_ref) &&
        sha == car&.merge_request&.merge_params&.dig('train_ref', 'commit_sha')
    end

    def create_pipeline!
      result = MergeTrains::CreatePipelineService.new(merge_train_car.project, merge_train_car.user)
        .execute(merge_train_car.merge_request, merge_train_car.previous_ref, create_mergeable_train_ref?)

      raise ProcessError, pipeline_creation_error(result[:message]) unless result[:status] == :success

      pipeline = result[:pipeline]
      cancel_pipeline!(merge_train_car.pipeline, pipeline)
      merge_train_car.refresh_pipeline!(pipeline.id)

      pipeline
    end

    def cancel_pipeline!(pipeline, new_pipeline)
      ::Ci::CancelPipelineService
        .new(pipeline: pipeline, current_user: nil, auto_canceled_by_pipeline: new_pipeline)
        .force_execute
    rescue ActiveRecord::StaleObjectError
      # Often the pipeline has already been canceled by the auto-cancellation
      # mechanism when new pipelines for the same ref are created.
      # In this case, we can ignore the exception as it's already canceled.
    end

    def merge!
      merge_train_car.start_merge!

      merge_options = { skip_discussions_check: true, check_mergeability_retry_lease: true }
      merge_options[:merge_strategy] = MergeRequests::MergeStrategies::FromTrainRef if merge_from_train_ref?

      # Marks this as the merge train's own merge so it is exempt from merge train enforcement.
      merge_params = merge_request.merge_params.with_indifferent_access.merge(merging_via_merge_train: true)

      MergeRequests::MergeService.new(project: project, current_user: merge_user, params: merge_params)
        .execute(merge_request, **merge_options)

      unless merge_request.merged?
        # MergeService turns a git error into merge_error even when the ref already moved
        # (for example a post-receive hook failure after UserFFBranch), so check before
        # treating it as unlanded.
        return reconcile_silently_merged! if merge_from_train_ref? && merge_commit_landed_on_target?

        raise ProcessError, "the merge could not be completed. #{merge_request.merge_error}".strip
      end

      merge_train_car.finish_merge!
    rescue ProcessError
      # The merge did not complete and nothing landed; abort as before.
      raise
    rescue StandardError => e
      reconcile_interrupted_merge!(e)
    end

    # ff_merge can land the commit on the target branch before the post-merge steps
    # finish; a transient failure in between must not abort and orphan the merge.
    # https://gitlab.com/gitlab-org/gitlab/-/issues/598924
    def reconcile_interrupted_merge!(error)
      merge_request.reset

      if merge_request.merged?
        # Partial success: the merge landed but a post-merge step failed. Record the
        # interrupting error before finishing the car so it is not silently swallowed.
        Gitlab::ErrorTracking.track_exception(
          error,
          merge_request_id: merge_request.id,
          merge_request_iid: merge_request.iid,
          project_id: merge_request.target_project_id,
          handler: 'reconcile_interrupted_merge'
        )

        finish_already_merged_car
        return
      end

      # Only recover when this attempt actually landed the merge commit on the target
      # branch; a stale merged_commit_sha from a prior aborted attempt must not qualify.
      raise error unless merge_commit_landed_on_target?

      reconcile_silently_merged!
    end

    # A post-merge step failed after the MR was already marked merged: the merge
    # itself is done, so just finish the car (mirrors handle_merged_stuck_car).
    def finish_already_merged_car
      merge_train_car.finish_merge! if merge_train_car.merging?
      enqueue_source_branch_deletion
    end

    # Runs the same post-merge follow-through as a normal merge (PostMergeService is
    # idempotent via its own `merged?` guard): sets merged_at, fires hooks and
    # notifications, closes issues and deletes the source branch. Shared by the
    # immediate reconcile and the stuck-car unstick path so both fully finalise.
    def finalize_silently_merged_merge!
      record_landed_merge_commit_sha

      MergeRequests::PostMergeService
        .new(project: project, current_user: merge_user, params: { delete_source_branch: delete_source_branch? })
        .execute(merge_request)

      enqueue_source_branch_deletion
      merge_train_car.finish_merge!
    end

    # MergeService#commit is the only writer of merged_commit_sha, and its update! is
    # exactly what can fail in this window. Persist the landed shas before the post-merge
    # (as the manual-merge refresh path does) so the reader does not fall back to
    # diff_head_sha (the un-rebased source tip). Skip if MergeService already recorded them.
    def record_landed_merge_commit_sha
      return if merge_request.read_attribute(:merged_commit_sha).present?

      merge_request.assign_attributes(landed_merge_commit_attributes)
    end

    # The shas MergeService#commit records. From the train ref these include
    # merge_commit_sha and squash_commit_sha, which commit_to_revert needs for the
    # Revert and Cherry-pick buttons. Other strategies have no landed sha to record
    # here: their only source is merged_commit_sha, which the caller found blank.
    def landed_merge_commit_attributes
      return {} unless merge_from_train_ref?

      train_ref = merge_request.merge_params.with_indifferent_access.fetch('train_ref', {})

      {
        merged_commit_sha: train_ref['commit_sha'],
        merge_commit_sha: train_ref['merge_commit_sha'],
        squash_commit_sha: train_ref['squash_commit_sha']
      }.compact_blank
    end

    # after_merge normally enqueues this outside PostMergeService, so both reconcile
    # windows must enqueue it themselves when the source branch removal was requested.
    # A successful merge may have already enqueued it; a second enqueue is intentional
    # and harmless because DeleteSourceBranchWorker is idempotent.
    def enqueue_source_branch_deletion
      return unless delete_source_branch?

      # Hold the branch-deletion lease until DeleteSourceBranchWorker deletes the branch
      # and releases it, so another MR targeting this source branch cannot merge into a
      # branch that is about to disappear (MergeService#target_branch_pending_deletion_check!).
      # MergeService normally holds it, but its ensure released it when the interrupted
      # merge left the MR unmerged.
      obtain_branch_deletion_lease

      MergeRequests::DeleteSourceBranchWorker.perform_async(
        merge_request.id, merge_request.source_branch_sha, merge_user.id
      )
    end

    def obtain_branch_deletion_lease
      lease_key = MergeRequests::DeleteSourceBranchWorker.lease_key(
        merge_request.source_project_id, merge_request.source_branch
      )

      Gitlab::ExclusiveLease
        .new(lease_key, timeout: MergeRequests::DeleteSourceBranchWorker::LEASE_TIMEOUT)
        .try_obtain
    end

    # Immediate reconcile after an interrupted merge. On failure raise ReconcileError
    # so the worker retries without aborting, preserving the car for unstick! later.
    def reconcile_silently_merged!
      finalize_silently_merged_merge!

      Gitlab::AppLogger.info(
        message: 'Reconciled silently-merged merge train merge',
        merge_request_id: merge_request.id,
        merge_request_iid: merge_request.iid,
        project_id: merge_request.target_project_id
      )
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(
        e,
        merge_request_id: merge_request.id,
        merge_request_iid: merge_request.iid,
        project_id: merge_request.target_project_id,
        handler: 'reconcile_silently_merged'
      )

      raise ReconcileError, 'silently-merged reconciliation failed'
    end

    # Mirrors MergeRequest#squash_commit_reachable_from_target_branch?: proves the
    # recorded merge commit is actually reachable from the target branch head, so a
    # stale merged_commit_sha from a prior aborted attempt is not mistaken for success.
    def merge_commit_landed_on_target?
      landed_sha = landed_merge_commit_sha
      return false if landed_sha.blank?

      repository = merge_request.target_project.repository
      return false unless repository.exists?

      target_head = repository.commit(merge_request.target_branch)

      # Repository#commit swallows Gitaly errors to nil (Gitlab::Git::Commit.find),
      # so a nil target head means "could not determine", not "the branch is empty".
      # Retry via ReconcileError instead of returning false, which would abort and
      # destroy the car with no stuck-car sweeper backstop.
      raise ReconcileError, 'could not determine the target branch head' if target_head.nil?

      repository.ancestor?(landed_sha, target_head.sha)
    rescue ReconcileError
      raise
    rescue StandardError => e
      # A transient failure while checking (e.g. a Gitaly deadline) must not abort;
      # retry via ReconcileError so the car is preserved for a later run.
      Gitlab::ErrorTracking.track_exception(
        e,
        merge_request_id: merge_request.id,
        merge_request_iid: merge_request.iid,
        project_id: merge_request.target_project_id,
        method: :merge_commit_landed_on_target?
      )

      raise ReconcileError, 'could not determine whether the merge landed'
    end

    # For FromTrainRef the landed commit is by construction exactly the current train
    # ref sha, so use only that: a stale merged_commit_sha left by a prior aborted
    # attempt could still be reachable from the target and would falsely qualify.
    # Otherwise use merged_commit_sha via read_attribute, because the MergeRequest
    # getter returns nil until the MR is merged?, which it is not here yet.
    def landed_merge_commit_sha
      if merge_from_train_ref?
        return merge_request.merge_params.with_indifferent_access.dig('train_ref', 'commit_sha')
      end

      merge_request.read_attribute(:merged_commit_sha).presence
    end

    def delete_source_branch?
      merge_request.merge_params.with_indifferent_access
        .fetch('should_remove_source_branch', merge_request.force_remove_source_branch?) &&
        merge_request.can_remove_source_branch?(merge_user)
    end
    strong_memoize_attr :delete_source_branch?

    def merge_train_car
      merge_request.merge_train_car
    end

    def merge_user
      merge_request.merge_user
    end

    def require_recreate?
      params[:require_recreate]
    end

    def abort(error)
      AutoMerge::MergeTrainService.new(project, merge_train_car.user)
        .abort(merge_request, error.message, process_next: false)

      error(error.message)
    end

    def log_running_security_scans
      Gitlab::AppLogger.warn("Security scans running") if merge_request.running_scan_result_policy_violations.any?
    end
  end
end
