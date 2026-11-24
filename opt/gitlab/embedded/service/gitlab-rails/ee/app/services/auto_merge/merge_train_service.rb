# frozen_string_literal: true

module AutoMerge
  class MergeTrainService < AutoMerge::BaseService
    extend Gitlab::Utils::Override

    override :execute
    def execute(merge_request)
      # No-op if already on the train. Especially important because assigning a
      # duplicate has_one association with build_#{association} below would
      # permanently delete any pre-existing one, regardless of whether the new
      # one eventually gets saved. Just destroying a car is not safe and can
      # leave the train in an inconsistent state. See #cancel and #abort for the
      # extra steps necessary.
      return if merge_request.on_train?

      merge_request.build_merge_train_car(
        user: current_user,
        target_project: merge_request.target_project,
        target_branch: merge_request.target_branch
      )
      super do
        SystemNoteService.merge_train(merge_request, project, current_user, merge_request.merge_train_car)
      end
    end

    override :process
    def process(merge_request)
      return unless merge_request.on_train?

      ::MergeTrains::RefreshWorker
        .perform_async(merge_request.target_project_id, merge_request.target_branch)
    end

    override :cancel
    def cancel(merge_request)
      # Before dropping a merge request from a merge train, get the next
      # merge request in order to refresh it later.
      next_car = merge_request.merge_train_car&.any_next

      super do
        if merge_request.merge_train_car&.destroy
          SystemNoteService.cancel_merge_train(merge_request, project, current_user)
          next_car.outdate_pipeline if next_car&.active?
        end
      end
    end

    override :abort
    def abort(merge_request, reason, process_next: true)
      # Before dropping a merge request from a merge train, get the next
      # merge request in order to refresh it later.
      next_car = merge_request.merge_train_car&.any_next

      super(merge_request, reason) do
        if merge_request.merge_train_car&.destroy
          SystemNoteService.abort_merge_train(merge_request, project, current_user, reason)
          GraphqlTriggers.merge_request_merge_status_updated(merge_request)
          next_car.outdate_pipeline if next_car&.active? && process_next
        end
      end
    end

    # availability_details are responsible for validating whether the service is available_for a merge request and sets
    # an unavailable_reason if it is not
    override :availability_details
    def availability_details(merge_request)
      super do
        unless merge_request.project.merge_trains_enabled?
          next AutoMerge::AvailabilityCheck.error(unavailable_reason: :merge_trains_disabled)
        end

        pipeline = merge_request.diff_head_pipeline
        next AutoMerge::AvailabilityCheck.error(unavailable_reason: :missing_diff_head_pipeline) unless pipeline

        # When pipelines are not required to succeed, we also allow blocked and
        # canceling pipelines, because otherwise the only merge action would be an immediate merge.
        if pipeline.complete? ||
            (!merge_request.only_allow_merge_if_pipeline_succeeds? && (pipeline.canceling? || pipeline.blocked?))
          next AutoMerge::AvailabilityCheck.success
        end

        AvailabilityCheck.error(unavailable_reason: :incomplete_diff_head_pipeline)
      end
    end

    private

    override :skippable_available_for_checks
    def skippable_available_for_checks(merge_request)
      # Skip the conflict check when coming from
      # AddToMergeTrainWhenPipelineSucceedsService or AddToMergeTrainWhenChecksPassService
      # because this check fails any time mergeability is being re-evaluated, even
      # if there is actually no conflict. When we're already in the middle of an
      # auto-merge in a project using merge trains, a failure of this check is usually a
      # false positive. And in the worst case, the conflict will surface when attempting
      # to build the train ref instead, and the MR will be removed from the train
      # with a more informative message.
      skip_conflict_check = merge_request.auto_merge_strategy ==
        AutoMergeService::STRATEGY_ADD_TO_MERGE_TRAIN_WHEN_CHECKS_PASS

      super.merge(
        skip_conflict_check: skip_conflict_check || readd_after_completed_train_pipeline?(merge_request)
      )
    end

    # A merge request dropped from the train keeps that train's finished pipeline as its
    # head pipeline. Every push to a busy target branch marks it unchecked, so the conflict
    # check returns `checking`, which hides this strategy and offers
    # add_to_merge_train_when_checks_pass in its place.
    # See https://gitlab.com/gitlab-org/gitlab/-/issues/627635.
    def readd_after_completed_train_pipeline?(merge_request)
      pipeline = merge_request.diff_head_pipeline
      return false unless pipeline

      !merge_request.on_train? && pipeline.completed_merge_train_pipeline?
    end

    override :clearable_auto_merge_parameters
    def clearable_auto_merge_parameters
      super + %w[train_ref]
    end
  end
end
