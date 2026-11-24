# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    module PipelineExecutionPolicies
      class CreateProjectSchedulesService
        include Gitlab::Loggable

        EVENT_KEY = 'scheduled_pipeline_execution_policy_schedule_persistence_failure'

        def initialize(project:, security_policy:)
          @project = project
          @security_policy = security_policy
        end

        def execute
          schedules = security_policy.content.fetch("schedules")

          security_policy.transaction do
            security_policy
              .security_pipeline_execution_project_schedules
              .for_project(project)
              .delete_all

            security_policy.security_pipeline_execution_project_schedules.create!(attributes(schedules))
          end

          ServiceResponse.success
        rescue StandardError => e
          log_project_schedules_creation_error(e, security_policy)

          raise e
        end

        private

        attr_reader :project, :security_policy

        def attributes(schedules)
          intervals(schedules).map do |interval|
            {
              project_id: project.id,
              cron: interval.cron,
              cron_timezone: interval.time_zone,
              time_window_seconds: interval.time_window,
              snoozed_until: interval.snoozed_until
            }
          end
        end

        def intervals(schedules)
          Gitlab::Security::Orchestration::PipelineExecutionPolicies::Intervals.from_schedules(schedules)
        end

        def log_project_schedules_creation_error(error, policy)
          Gitlab::AppJsonLogger.error(
            build_structured_payload(
              event: EVENT_KEY,
              exception_class: error.class.name,
              exception_message: error.message,
              project_id: project.id,
              policy_id: policy.id))
        end
      end
    end
  end
end
