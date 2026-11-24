# frozen_string_literal: true

module Security
  module PipelineExecutionPolicies
    class CreateScheduledPipelineService
      PIPELINE_SOURCE = :pipeline_execution_policy_schedule
      EVENT_KEY = 'scheduled_pipeline_execution_policy_failure'

      def initialize(project:, ci_content:, policy:, branch: nil, schedule_id: nil)
        @project = project
        @ci_content = ci_content
        @branch = branch || project.default_branch_or_main
        @policy = policy
        @schedule_id = schedule_id
      end

      def execute
        ensure_security_policy_bot

        create_pipeline.tap do |result|
          log_pipeline_creation_failure(result) if result.error?
        end
      end

      private

      attr_reader :project, :ci_content, :branch, :policy, :schedule_id

      def create_pipeline
        yaml_content = ci_content.deep_stringify_keys.to_yaml
        Ci::CreatePipelineService.new(
          project,
          project.security_policy_bot,
          ref: branch
        ).execute(PIPELINE_SOURCE,
          content: yaml_content,
          pipeline_execution_policy_context_block: ->(args) do
            args.merge(current_policy: scheduled_policy_context)
          end,
          ignore_skip_ci: true)
      end

      def scheduled_policy_context
        ::Security::PipelineExecutionPolicy::Config.new(
          policy: policy_hash,
          policy_config: policy.security_orchestration_policy_configuration,
          policy_index: policy.policy_index
        )
      end

      def policy_hash
        policy.content.merge(
          name: policy.name,
          variables_override: scheduled_variables_override
        ).with_indifferent_access
      end

      def scheduled_variables_override
        policy.content.with_indifferent_access[:variables_override] || { allowed: false }
      end

      def ensure_security_policy_bot
        return if project.security_policy_bot

        Security::Orchestration::CreateBotService
          .new(project, nil, skip_authorization: true)
          .execute

        project.reset
      end

      def log_pipeline_creation_failure(result)
        Gitlab::AppJsonLogger.error(
          event: EVENT_KEY,
          message: result.message,
          reason: result.reason,
          project_id: project.id,
          schedule_id: schedule_id,
          policy_id: policy.id,
          branch: branch
        )
      end
    end
  end
end
