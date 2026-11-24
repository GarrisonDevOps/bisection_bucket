# frozen_string_literal: true

# Shared logic for workers that create pipelines from scan execution policies.
# Used by CreatePipelineWorker and RunScheduleWorker.
module Security
  module ScanExecutionPolicies
    module PipelineCreation
      extend ActiveSupport::Concern

      included do
        include Gitlab::InternalEventsTracking
      end

      private

      def actions_for(rule_schedule)
        policy = rule_schedule.policy
        return [] if policy.blank?

        actions = policy[:actions]
        action_limit = Gitlab::CurrentSettings.scan_execution_policies_action_limit

        return actions if action_limit == 0

        actions.first(action_limit)
      end

      def create_scan_execution_pipeline(project:, user:, rule_schedule:, branch:)
        actions = actions_for(rule_schedule)
        return if actions.blank?

        policy_name = rule_schedule.policy[:name]

        # Agentic actions start a Duo flow instead of a CI job. They run after the CI branch, so a
        # CI error that makes Sidekiq retry cannot start a second flow.
        agentic_actions, ci_actions = actions.partition do |action|
          ::Security::ScanExecutionPolicy.agentic_scan_type?(action[:scan])
        end

        return run_agentic_scans(project, agentic_actions, branch, policy_name) if ci_actions.blank?

        service_result = ::Security::SecurityOrchestrationPolicies::CreatePipelineService
                  .new(project: project, current_user: user,
                    params: { actions: ci_actions, branch: branch, policy_name: policy_name })
                  .execute

        track_creation_event(project, rule_schedule, ci_actions.size, service_result[:status])

        if service_result[:status] == :success
          record_policy_pipelines(project, rule_schedule, service_result[:payload])
        else
          log_pipeline_creation_error(project, user, rule_schedule, branch, service_result[:message])

          ::Security::Policies::ScheduledScansNotEnforcedAuditWorker.perform_async(
            project.id, user.id, rule_schedule.id, branch
          )
        end

        run_agentic_scans(project, agentic_actions, branch, policy_name) if agentic_actions.any?
      end

      def run_agentic_scans(project, actions, branch, policy_name)
        ::Security::SecurityOrchestrationPolicies::RunScheduledAgenticScanService
          .new(project: project, params: { actions: actions, branch: branch, policy_name: policy_name })
          .execute
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_and_raise_for_dev_exception(
          e, project_id: project.id, branch: branch, policy_name: policy_name
        )
      end

      def track_creation_event(project, rule_schedule, scans_count, result)
        track_internal_event(
          'enforce_scheduled_scan_execution_policy_in_project',
          project: project,
          additional_properties: {
            value: scans_count,
            label: result.to_s,
            property: rule_schedule.policy_source,
            time_window: rule_schedule.time_window.present? ? 1 : 0
          }
        )
      end

      def record_policy_pipelines(project, rule_schedule, pipelines_payload)
        return unless pipelines_payload.is_a?(Hash)

        security_policy = security_policy_for(rule_schedule)

        unless security_policy
          Gitlab::AppJsonLogger.warn(
            message: 'Security policy not found for rule schedule',
            rule_schedule_id: rule_schedule.id,
            security_orchestration_policy_configuration_id:
              rule_schedule.security_orchestration_policy_configuration_id,
            policy_index: rule_schedule.policy_index
          )
          return
        end

        # CreatePipelineService returns a hash payload (for example, :pipeline_scan
        # and :on_demand), so we iterate over all values defensively.
        pipelines_payload.each_value do |pipeline|
          next unless pipeline.is_a?(::Ci::Pipeline)

          Security::PolicySchedulePipeline.safe_create(
            security_policy: security_policy,
            pipeline: pipeline,
            project: project
          )
        end
      end

      def security_policy_for(rule_schedule)
        Security::Policy
          .for_rule_schedule(rule_schedule)
          .select(:id)
          .first
      end

      def log_pipeline_creation_error(project, user, rule_schedule, branch, message)
        ::Gitlab::AppJsonLogger.warn(
          build_structured_payload(
            message: message,
            project_id: project.id,
            Labkit::Fields::GL_USER_ID => user.id,
            security_orchestration_policy_configuration_id:
              rule_schedule.security_orchestration_policy_configuration_id,
            rule_schedule_id: rule_schedule.id,
            branch: branch
          )
        )
      end
    end
  end
end
