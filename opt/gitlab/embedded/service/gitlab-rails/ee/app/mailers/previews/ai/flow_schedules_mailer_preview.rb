# frozen_string_literal: true

module Ai
  class FlowSchedulesMailerPreview < ActionMailer::Preview
    def ai_flow_schedule_deactivated_email
      schedule = fake_schedule(
        consecutive_failure_count: Ai::FlowSchedule::MAX_CONSECUTIVE_FAILURES,
        last_run_error: 'Service account is no longer available'
      )
      Notify.ai_flow_schedule_deactivated_email(schedule, recipient(schedule))
    end

    def ai_flow_schedule_failure_email
      schedule = fake_schedule(consecutive_failure_count: 1, last_run_error: 'Execution timed out')
      Notify.ai_flow_schedule_failure_email(schedule, recipient(schedule))
    end

    private

    # Unsaved record: flow schedule failures/deactivations are transient, so there's
    # no guarantee a real Ai::FlowSchedule exists to preview against.
    def fake_schedule(attrs)
      Ai::FlowSchedule.new(attrs.merge(project: Project.last, description: 'Nightly triage'))
    end

    def recipient(schedule)
      schedule.project.owners_and_maintainers.first || User.first
    end
  end
end
