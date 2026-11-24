# frozen_string_literal: true

module SecretsManagement
  # Shared flow for SecretsManager InitiateDeprovision services. Validates
  # the secrets manager state, destroys the SM row, and (optionally)
  # enqueues the deprovision worker for snappy follow-through.
  #
  # Destroying the row fires the AFTER DELETE trigger installed by
  # gitlab-org/gitlab#600290, which inserts a deprovision maintenance
  # task with snapshot ids read off the SM's denormalized columns
  # (`organization_id`, `root_namespace_id`, `project_id` / `group_id`).
  # The task then drives the OpenBao cleanup worker.
  #
  # `enqueue_worker:` controls whether `perform_async` is called inline:
  #   - GraphQL deprovision mutations pass the default `true` so the
  #     user sees the deprovision drain promptly.
  #   - Destroy/transfer hooks would pass `false` if they called this
  #     service, but in the trigger-driven world hooks no longer call
  #     this service at all for destroy. Transfer still does (parent
  #     survives, so CASCADE does not fire), and passes `false` because
  #     it runs inside the parent's transaction and a `perform_async`
  #     there could fire before commit.
  #
  # Including classes must implement:
  # - `not_found_message`               -- error when secrets_manager is nil
  # - `success_payload`                 -- hash returned on success
  # - `lookup_pending_deprovision_task` -- find the task the trigger
  #     just created (used to enqueue the worker)
  # - `enqueue_deprovision_worker(task)` -- scope-specific worker enqueue
  # - `pending_deprovision_task_without_sm?` -- task-table lookup by snapshot
  #     resource id when secrets_manager is nil
  module InitiateDeprovisionServiceHelpers
    extend ActiveSupport::Concern
    include Helpers::ErrorResponseHelper

    def execute(enqueue_worker: true)
      # When the SM row is gone but a deprovision task is still pending
      # for the snapshot resource id, surface that to the caller as
      # "in progress" rather than "not found". The SM-gone case is the
      # steady state under the trigger-based design (gitlab-org/gitlab#600290)
      # where CASCADE deletes the SM row before OpenBao cleanup completes.
      if secrets_manager.nil?
        return deprovision_in_progress_response if pending_deprovision_task_without_sm?

        return ServiceResponse.error(message: not_found_message)
      end

      return deprovision_in_progress_response if secrets_manager.pending_deprovision_task?
      return secrets_manager_inactive_response unless secrets_manager.active_after_refresh?

      # Destroy fires the AFTER DELETE trigger which inserts the
      # deprovision maintenance task. The cron picks the task up if no
      # one enqueues a worker for it directly.
      secrets_manager.destroy!

      if enqueue_worker
        task = lookup_pending_deprovision_task
        enqueue_deprovision_worker(task) if task
      end

      ServiceResponse.success(payload: success_payload)
    end

    private

    attr_reader :secrets_manager, :current_user

    def not_found_message
      raise NotImplementedError
    end

    def lookup_pending_deprovision_task
      raise NotImplementedError
    end

    def enqueue_deprovision_worker(_task)
      raise NotImplementedError
    end

    def success_payload
      raise NotImplementedError
    end

    def pending_deprovision_task_without_sm?
      raise NotImplementedError
    end
  end
end
