# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class CancelAssociatedPipelinesWorker
      include ApplicationWorker

      idempotent!
      data_consistency :sticky
      feature_category :duo_agent_platform
      urgency :high
      defer_on_database_health_signal :gitlab_main, [:duo_workflows_workflows]

      def perform(workflow_id, user_id)
        workflow = ::Ai::DuoWorkflows::Workflow.find_by_id(workflow_id)
        return unless workflow

        user = ::User.find_by_id(user_id)
        return unless user

        pipelines = workflow.associated_pipelines

        pipelines.each do |pipeline|
          next unless pipeline.cancelable?

          # rate_limit: false because this is an automated caller that cancels every
          # associated pipeline in a loop; it must not be throttled like a user's clicks.
          result = ::Ci::CancelPipelineService.new(
            pipeline: pipeline,
            current_user: user,
            rate_limit: false
          ).execute

          next unless result.error?

          Gitlab::ErrorTracking.log_exception(
            StandardError.new("Failed to cancel pipeline"),
            workflow_id: workflow.id,
            pipeline_id: pipeline.id,
            message: result.message
          )
        end
      end
    end
  end
end
