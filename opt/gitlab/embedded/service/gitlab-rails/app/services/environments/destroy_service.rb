# frozen_string_literal: true

module Environments
  class DestroyService < BaseService
    BATCH_SIZE = 500

    def execute(environment)
      unless can?(current_user, :destroy_environment, environment)
        return ServiceResponse.error(
          message: 'Unauthorized to delete the environment'
        )
      end

      unsafe_execute!(environment)
    end

    ##
    # Deletes the environment without checking user permissions. This
    # should only be used if initiated by a system action and a user
    # cannot be specified.
    def unsafe_execute!(environment, budget: DestroyBudget.new(user: current_user))
      if Feature.enabled?(:environment_delete_in_batches, environment.project)
        return destroy_in_batches(environment, budget)
      end

      environment.destroy

      destroy_response(environment)
    end

    private

    # Each batch commits on its own, so a request stopped early keeps its progress and a retry continues from it
    def destroy_in_batches(environment, budget)
      stop_reason = delete_job_environments(environment, budget) ||
        delete_merge_request_links(environment, budget) ||
        delete_deployments(environment, budget)

      return rows_throttled_error if stop_reason == :throttled
      return incomplete_error if stop_reason == :incomplete
      return not_stopped_error if stop_reason == :not_stopped

      destroy_stopped(environment)
    end

    def delete_job_environments(environment, budget)
      row_count = nil

      loop do
        stop_reason = next_batch_stop_reason(environment, budget)

        if stop_reason
          # A full last batch can leave nothing to stop for, so the request goes on to delete the environment
          return if row_count && !::Environments::Job.exists_for?(environment)

          return stop_reason
        end

        row_count = ::Environments::Job.delete_batch_for_environment(environment, BATCH_SIZE)
        budget.charge(row_count)

        # A concurrent delete can take the rows a batch selected, so a short batch doesn't mean none remain
        return if row_count < BATCH_SIZE && !::Environments::Job.exists_for?(environment)
      end
    end

    def delete_merge_request_links(environment, budget)
      stop_reason = nil

      ::DeploymentMergeRequest.each_batch_for_environment(environment, of: BATCH_SIZE) do |links|
        stop_reason = next_batch_stop_reason(environment, budget)
        break if stop_reason

        budget.charge(links.delete_all)
      end

      stop_reason
    end

    def delete_deployments(environment, budget)
      stop_reason = nil

      environment.all_deployments.each_batch(of: BATCH_SIZE) do |deployments|
        stop_reason = next_batch_stop_reason(environment, budget)
        break if stop_reason

        delete_deployment_batch(environment, deployments, budget)
      end

      stop_reason
    end

    # Gitaly can fail to delete the refs after the batch's rows are deleted, so we
    # charge the rows first and go on to delete the rest, leaving the refs behind.
    def delete_deployment_batch(environment, deployments, budget)
      deployments.fast_destroy_all { |row_count| budget.charge(row_count) }
    rescue ::Gitlab::Git::BaseError => e
      ::Gitlab::ErrorTracking.track_exception(e, environment_id: environment.id, project_id: environment.project_id)
    end

    # A deployment that succeeds between batches makes the environment available, so we stop before deleting more of it
    def next_batch_stop_reason(environment, budget)
      budget.stop_reason(batch_size: BATCH_SIZE) ||
        (:not_stopped if ::Environment.id_in(environment).without_state(:stopped).exists?)
    end

    def destroy_stopped(environment)
      stopped = environment.with_lock do
        environment.destroy if environment.stopped?
        environment.stopped?
      end

      return destroy_response(environment) if stopped

      not_stopped_error
    rescue ActiveRecord::RecordNotFound
      # A concurrent request deleted the environment first
      ServiceResponse.success
    end

    def destroy_response(environment)
      unless environment.destroyed?
        return ServiceResponse.error(
          message: 'Attempted to destroy the environment but failed'
        )
      end

      ServiceResponse.success
    end

    def rows_throttled_error
      ServiceResponse.error(message: ::Gitlab::ApplicationRateLimiter.throttled_error_message, reason: :throttled)
    end

    def not_stopped_error
      ServiceResponse.error(message: _('Environment must be stopped before it can be deleted.'), reason: :not_stopped)
    end

    def incomplete_error
      ServiceResponse.error(
        message: _('The environment was partially deleted. Retry the request to finish deleting it.'),
        reason: :incomplete
      )
    end
  end
end
