# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class FailStuckWorkflowsWorker
      include ::ApplicationWorker
      include ::CronjobQueue

      idempotent!
      worker_resource_boundary :cpu
      urgency :low
      feature_category :duo_agent_platform
      data_consistency :sticky

      # Every run updates stuck rows in duo_workflows_workflows, so back off while that table is under pressure.
      defer_on_database_health_signal :gitlab_main_org, [:duo_workflows_workflows], 1.minute

      def perform
        ::Ai::DuoWorkflows::CleanStuckWorkflowsService.new.execute
      end
    end
  end
end
