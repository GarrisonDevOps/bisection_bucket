# frozen_string_literal: true

module SecretsManagement
  # Shared flow for SecretsManager Initialize services. Runs the SM-exists
  # guard, runs any scope-specific guards, then creates the SM record and
  # the `:provision` maintenance task in one transaction, enqueues the
  # async worker, and returns a scope-specific success payload.
  #
  # Anchoring the provision flow on a maintenance task gives the worker
  # the same crash-recovery guarantees the deprovision flow already has:
  # if the async worker dies, the task is left stale and the cron worker
  # retries it. The provision service is designed to be idempotent.
  #
  # The SM-exists guard runs in `execute` itself, not in the overridable
  # `ensure_secrets_manager_allowed_on_resource` hook, so subclasses
  # cannot accidentally skip it when they override that hook.
  #
  # Including classes must implement:
  # - `resource`                        -- project or group record
  # - `create_secrets_manager`          -- create + persist the SM record
  # - `create_maintenance_task(sm)`     -- create + persist the provision task
  # - `enqueue_provision_worker(task)`  -- async worker enqueue
  # - `track_enabled_event`             -- internal event for a new SM
  #
  # Including classes may override:
  # - `ensure_secrets_manager_allowed_on_resource` for additional guards
  module InitializeServiceHelpers
    extend ActiveSupport::Concern
    include Gitlab::InternalEventsTracking

    delegate :secrets_manager, to: :resource

    def execute
      # Check the deprovision gate first. When both gates would fire
      # (SM row still exists AND a deprovision task is pending; the
      # common state during today's async deprovision window), the
      # in-progress message is more informative for the caller than
      # "already initialized".
      return deprovision_in_progress_response if deprovision_in_progress?
      return secrets_manager_exists_response if secrets_manager.present?

      result = ensure_secrets_manager_allowed_on_resource
      return result if result.error?

      entitlement_error = validate_entitlement(action: 'initialized')
      return entitlement_error if entitlement_error

      secrets_manager_record = nil

      # SM creation and maintenance task creation must commit together. If
      # only one succeeds we'd be stuck: an SM with no task (no retry on
      # worker death) or a task pointing at no SM. Enqueue is outside the
      # transaction so a rollback never leaves a Sidekiq job pointing at
      # a task that doesn't exist.
      task = ApplicationRecord.transaction do
        secrets_manager_record = create_secrets_manager
        create_maintenance_task(secrets_manager_record)
      end

      enqueue_provision_worker(task)
      # Here rather than in the callers: the trial and add-on mutations provision too.
      track_enabled_event

      ServiceResponse.success(payload: success_payload(secrets_manager_record))
    end

    private

    def resource_type
      resource.model_name.singular
    end

    def secrets_manager_exists_response
      # reason lets callers treat this answer as benign without coupling
      # to the message wording (EnableAddOn retries past it on re-click).
      ServiceResponse.error(
        message: "Secrets manager already initialized for the #{resource_type}.",
        reason: :already_initialized
      )
    end

    # Block init while a deprovision is in flight. Today the SM-exists
    # gate above catches this case because deprovision keeps the SM row
    # around until the worker finishes. The task-based gate exists to
    # keep the same protection once the trigger-based deprovision flow
    # lands (gitlab-org/gitlab#600290): the SM row will be deleted as
    # part of the cascade before OpenBao cleanup completes, so the
    # maintenance task becomes the only durable signal we can use.
    def deprovision_in_progress?
      false
    end

    def deprovision_in_progress_response
      ServiceResponse.error(message: "Secrets manager deprovision is in progress for the #{resource_type}.")
    end

    def ensure_secrets_manager_allowed_on_resource
      ServiceResponse.success
    end

    def success_payload(secrets_manager)
      { "#{resource_type}_secrets_manager": secrets_manager }
    end

    def resource
      raise NotImplementedError
    end

    def create_secrets_manager
      raise NotImplementedError
    end

    def create_maintenance_task(_secrets_manager)
      raise NotImplementedError
    end

    def enqueue_provision_worker(_task)
      raise NotImplementedError
    end

    def track_enabled_event
      raise NotImplementedError
    end
  end
end
