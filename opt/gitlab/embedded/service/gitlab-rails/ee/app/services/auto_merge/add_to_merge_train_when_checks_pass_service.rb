# frozen_string_literal: true

# rubocop:disable Gitlab/BoundedContexts -- TODO refactor to use bounded context
module AutoMerge
  class AddToMergeTrainWhenChecksPassService < AutoMerge::BaseService
    extend Gitlab::Utils::Override

    def execute(merge_request)
      super do
        sha = merge_request.diff_head_pipeline&.sha || merge_request.diff_head_sha
        SystemNoteService.add_to_merge_train_when_checks_pass(merge_request, project, current_user, sha)
      end
    end

    def process(merge_request)
      logger.info("Processing Automerge - AMTWCP")

      return unless merge_request.mergeable?(
        skip_conflict_check: true, skip_ci_check: readd_to_train?(merge_request), use_cache: false,
        check_order: :likely_to_fail_first
      )

      logger.info("Merge request mergeable - AMTWCP")

      merge_train_service = AutoMerge::MergeTrainService.new(project, merge_request.merge_user)

      unless merge_train_service.available_for?(merge_request)
        # A concurrent run may have added the merge request to the train while this one
        # was evaluating. Adding it flips `readd_to_train?` off, so the CI check comes
        # back and aborting here would destroy a car that is already doing its job.
        return if merge_request.reset.on_train?

        abort_message = merge_train_service.availability_details(merge_request).abort_message

        return abort(merge_request, abort_message)
      end

      merge_train_service.execute(merge_request)
    end

    def cancel(merge_request)
      super do
        SystemNoteService.cancel_add_to_merge_train_when_checks_pass(merge_request, project, current_user)
      end
    end

    def abort(merge_request, reason)
      # If the merge request is already on a merge train, we need to destroy the car
      # i.e. If the target branch is deleted which causes an abort with this strategy,
      # after the pipeline succeeded and was added
      #
      if merge_request.merge_train_car
        AutoMerge::MergeTrainService.new(project, current_user).abort(merge_request, reason)
        # Before the pipeline checks pass and was added to the merge train
      else
        super do
          SystemNoteService.abort_add_to_merge_train_when_checks_pass(merge_request, project, current_user, reason)
        end
      end
    end

    # availability_details are responsible for validating whether the service is available_for a merge request and sets
    # an unavailable_reason if it is not
    override :availability_details
    def availability_details(merge_request)
      super do
        default_error = AutoMerge::AvailabilityCheck.error
        next default_error unless merge_request.has_ci_enabled?

        next default_error if merge_request.mergeable? && !merge_request.diff_head_pipeline_considered_in_progress?

        unless merge_request.project.merge_trains_enabled?
          next AutoMerge::AvailabilityCheck.error(unavailable_reason: :merge_trains_disabled)
        end

        AutoMerge::AvailabilityCheck.success
      end
    end

    private

    # The merge request came off a merge train and its head pipeline is still that
    # train's finished pipeline. A completed merge train pipeline cannot be retried
    # (see Ci::Pipeline#retryable?), so requiring it to pass would strand the merge
    # request. A train pipeline that is still running, or a new pipeline being
    # created, supersedes it and is left to the normal CI check.
    def readd_to_train?(merge_request)
      pipeline = merge_request.diff_head_pipeline
      return false unless pipeline

      !merge_request.on_train? &&
        !merge_request.pipeline_creating? &&
        pipeline.completed_merge_train_pipeline?
    end
  end
end
# rubocop:enable Gitlab/BoundedContexts
