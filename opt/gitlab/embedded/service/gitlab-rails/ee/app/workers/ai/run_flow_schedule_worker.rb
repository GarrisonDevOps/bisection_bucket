# frozen_string_literal: true

module Ai
  class RunFlowScheduleWorker
    include ApplicationWorker

    data_consistency :sticky

    sidekiq_options retry: true
    feature_category :dap_triggers
    deduplicate :until_executed, including_scheduled: true
    idempotent!

    concurrency_limit -> { 100 }

    UNEXPECTED_ERROR_MESSAGE = 'Flow execution failed unexpectedly'

    EXCESS_ACCESS_MESSAGE = 'The service account holds more access than the flow, and could not be adjusted'

    SKIPPED_RUN_REASONS = %i[
      flow_disabled_by_feature_flag
      non_human_trigger_not_permitted
      usage_quota_exceeded
    ].freeze

    OUTCOME_MESSAGES = {
      succeeded: 'Scheduled flow run dispatched',
      skipped: 'Scheduled flow run skipped',
      failed: 'Scheduled flow run failed'
    }.freeze

    ERROR_MESSAGE_LIMIT = 1024

    def perform(schedule_id, options = {})
      schedule = ::Ai::FlowSchedule.find_by_id(schedule_id)

      error = validation_error(schedule, options)
      return log_skipped(schedule, error.reason, error.message, schedule_id: schedule_id) if error

      advance_next_run_at!(schedule) if options['scheduling']

      execute_flow(schedule)
    end

    private

    def validation_error(schedule, options)
      return skip_response('Schedule not found', :schedule_not_found) unless schedule

      return skip_response('Schedule is not active, skipping scheduled run', :schedule_inactive) unless schedule.active?

      return skip_response('Flow trigger not found for schedule', :flow_trigger_not_found) unless schedule.flow_trigger

      project = schedule.project
      return skip_response('Project not found for schedule', :project_not_found) unless project

      unless Feature.enabled?(:ai_flow_schedules, project)
        return skip_response('Flow schedules are not enabled for this project, skipping scheduled run',
          :schedules_feature_flag_disabled)
      end

      if project.self_or_ancestors_archived?
        return skip_response('Project or ancestors are archived', :project_archived)
      end

      if project.deletion_in_progress_or_scheduled_in_hierarchy_chain?
        return skip_response('Project, namespace or ancestors are scheduled for deletion',
          :project_pending_deletion)
      end

      if options['scheduling'] && schedule.next_run_at&.future?
        return skip_response('Schedule next run time is in future', :next_run_in_future)
      end

      nil
    end

    def skip_response(message, reason)
      ServiceResponse.error(message: message, reason: reason)
    end

    # Checked after next_run_at advances, not in validation_error, so resuming picks up at the
    # next tick instead of firing missed runs. Runs ahead of schedulable_target?:
    # a paused or disabled trigger must skip quietly regardless of other issues.
    def quiet_skip(flow_trigger, project)
      unless flow_trigger.active?
        return skip_response('Flow trigger is not active, skipping scheduled run', :trigger_inactive)
      end

      unless flow_trigger.scheduled?
        return skip_response('Flow trigger no longer runs on a schedule, skipping scheduled run',
          :trigger_not_scheduled)
      end

      unless flow_trigger.scheduled_triggers_beta_available?(project)
        return skip_response('Scheduled automations require experiment and beta features, skipping scheduled run',
          :beta_features_unavailable)
      end

      unless project.duo_scheduled_triggers_enabled
        return skip_response('Scheduled automations are turned off, skipping scheduled run',
          :scheduled_automations_disabled)
      end

      unless project.duo_remote_flows_enabled
        return skip_response('Flow execution is turned off, skipping scheduled run', :flow_execution_disabled)
      end

      nil
    end

    def advance_next_run_at!(schedule)
      # Advance next_run_at BEFORE execution to prevent duplicate runs
      # if the worker is retried or the cron fires again while executing.
      schedule.schedule_next_run!
    end

    def execute_flow(schedule)
      flow_trigger = schedule.flow_trigger
      project = schedule.project

      skip = quiet_skip(flow_trigger, project)
      return log_skipped(schedule, skip.reason, skip.message) if skip

      unless flow_trigger.schedulable_target?
        return handle_failure(schedule, ::Ai::FlowTrigger.unsupported_schedule_target_message,
          reason: :unsupported_target)
      end

      excess_access = reconcile_service_account_role(flow_trigger, project)
      return handle_failure(schedule, EXCESS_ACCESS_MESSAGE, reason: :excess_service_account_access) if excess_access

      response = ::Ai::FlowTriggers::RunService.new(
        project: project,
        flow_trigger: flow_trigger,
        trigger_source: :scheduled,
        flow_schedule: schedule
      ).execute({ event: :scheduled })

      # RunService returns [response, workflow] or just response
      response, _workflow = response if response.is_a?(Array)

      workflow_id = workflow_id_from(response)

      if response&.success?
        schedule.record_success!
        log_outcome(:succeeded, schedule, workflow_id: workflow_id)
      elsif skipped_run?(response)
        log_skipped(schedule, response.reason, "#{join_message(response.message)}, skipping scheduled run",
          workflow_id: workflow_id)
      else
        handle_failure(schedule, failure_message(response), reason: response&.reason || :run_service_error,
          workflow_id: workflow_id)
      end
    rescue StandardError => e
      track_error(schedule, e)
      handle_failure(schedule, UNEXPECTED_ERROR_MESSAGE, reason: :unexpected_error)
    end

    # Nothing observes a change to the flow account's role, so the account can
    # arrive at a run holding a role the flow no longer has. Reconciling here
    # rather than on a timer means the window is the run itself: it is also the
    # only moment the account can act.
    #
    # Returns true when the run must not proceed.
    def reconcile_service_account_role(flow_trigger, project)
      return false unless flow_trigger.autonomous_service_account_id
      return false unless Feature.enabled?(:autonomous_service_account_execution, project)

      result = ::Ai::FlowTriggers::SyncAutonomousServiceAccountRoleService.new(
        project: project,
        item_consumer: flow_trigger.ai_catalog_item_consumer,
        service_account_id: flow_trigger.autonomous_service_account_id
      ).execute

      result.payload[:excess_access]
    end

    def failure_message(response)
      return ::Ai::FlowTrigger.mixed_event_types_message if
        response&.reason == :autonomous_trigger_source_not_permitted

      response&.message || 'Unknown execution error'
    end

    def skipped_run?(response)
      response.present? && SKIPPED_RUN_REASONS.include?(response.reason)
    end

    def join_message(message)
      message.is_a?(String) ? message : Array(message).join(', ')
    end

    def handle_failure(schedule, error_message, reason:, workflow_id: nil)
      error_message = join_message(error_message)
      schedule.record_failure!(error_message)

      deactivated = schedule.deactivated_by_failures?

      log_outcome(:failed, schedule,
        reason: reason,
        error_message: error_message,
        workflow_id: workflow_id,
        consecutive_failure_count: schedule.consecutive_failure_count,
        deactivated: deactivated)

      if deactivated
        NotificationService.new.ai_flow_schedule_deactivated(schedule)
      else
        NotificationService.new.ai_flow_schedule_failed(schedule)
      end
    end

    def log_skipped(schedule, reason, message, schedule_id: nil, **extra)
      log_outcome(:skipped, schedule, reason: reason, error_message: message, schedule_id: schedule_id, **extra)
    end

    def log_outcome(outcome, schedule, reason: nil, error_message: nil, schedule_id: nil, workflow_id: nil, **extra)
      project = schedule&.project

      payload = build_structured_payload_labkit(
        ::Labkit::Fields::LOG_MESSAGE => OUTCOME_MESSAGES.fetch(outcome),
        outcome: outcome.to_s,
        outcome_reason: reason&.to_s,
        trigger_source: 'scheduled',
        flow_schedule_id: schedule&.id || schedule_id,
        flow_trigger_id: schedule&.ai_flow_trigger_id,
        ::Labkit::Fields::ERROR_MESSAGE => error_message&.truncate(ERROR_MESSAGE_LIMIT),
        ::Labkit::Fields::GL_PROJECT_ID => project&.id,
        ::Labkit::Fields::GL_ROOT_NAMESPACE_ID => project&.namespace&.traversal_ids&.first,
        ::Labkit::Fields::DUO_WORKFLOW_ID => workflow_id,
        **extra
      ).compact

      if outcome == :failed
        Gitlab::AppLogger.error(payload)
      else
        Gitlab::AppLogger.info(payload)
      end
    end

    def workflow_id_from(response)
      payload = response&.payload
      return unless payload.is_a?(Hash)

      payload[:workflow]&.id
    end

    def track_error(schedule, error)
      Gitlab::ErrorTracking.track_exception(
        error,
        schedule_id: schedule.id,
        flow_trigger_id: schedule.ai_flow_trigger_id
      )
    end
  end
end
