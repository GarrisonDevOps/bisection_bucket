# frozen_string_literal: true

module Security
  module PipelineExecutionPolicies
    class RunScheduleWorker
      include ApplicationWorker

      idempotent!
      deduplicate :until_executing, including_scheduled: true,
        ttl: Security::PipelineExecutionProjectSchedule::MAX_TIME_WINDOW
      urgency :throttled
      concurrency_limit -> { 1000 }
      data_consistency :sticky
      feature_category :security_policy_management

      def perform(schedule_id, options = {})
        raise(ArgumentError, 'options must be of type Hash') unless options.is_a?(Hash) || options.nil?

        schedule = Security::PipelineExecutionProjectSchedule.find_by_id(schedule_id) || return

        # Guards against a schedule outliving its project link, e.g. a race with the transfer cleanup.
        return unless schedule.security_policy&.linked_to_project?(schedule.project)

        unless schedule.policy_still_valid?
          log_revoked_schedule(schedule)

          return
        end

        if schedule.snoozed?
          ::Gitlab::InternalEvents.track_event('scheduled_pipeline_execution_policy_snoozed', project: schedule.project)

          return
        end

        branch = options.fetch('branch', schedule.project.default_branch_or_main)

        result = execute(schedule, branch)

        record_policy_pipeline(schedule, result) if result.success?

        track_pipeline_creation_event(schedule, result)
      end

      private

      def execute(schedule, branch)
        CreateScheduledPipelineService.new(
          project: schedule.project,
          ci_content: schedule.ci_content,
          branch: branch,
          policy: schedule.security_policy,
          schedule_id: schedule.id
        ).execute
      end

      def record_policy_pipeline(schedule, result)
        pipeline = result.payload
        return unless pipeline.is_a?(::Ci::Pipeline)

        Security::PolicySchedulePipeline.safe_create(
          security_policy: schedule.security_policy,
          pipeline: pipeline,
          project: schedule.project
        )
      end

      def track_pipeline_creation_event(schedule, result)
        ::Gitlab::InternalEvents.track_event(
          'execute_job_scheduled_pipeline_execution_policy',
          project: schedule.project,
          additional_properties: {
            label: result.status.to_s
          }
        )
      end

      def log_revoked_schedule(schedule)
        Gitlab::AppJsonLogger.warn(
          event: 'scheduled_pipeline_execution_policy_revoked',
          message: 'Scheduled PEP job skipped: policy is no longer valid for this project',
          Labkit::Fields::GL_PROJECT_ID => schedule.project_id,
          schedule_id: schedule.id,
          policy_id: schedule.security_policy_id,
          configuration_id: schedule.security_policy.security_orchestration_policy_configuration_id
        )
      end
    end
  end
end
