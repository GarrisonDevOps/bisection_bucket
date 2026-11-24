# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class SyncSessionArtifactWorker
      include ApplicationWorker

      idempotent!
      data_consistency :delayed
      feature_category :compliance_management
      urgency :low
      defer_on_database_health_signal :gitlab_main, [:duo_workflow_session_artifacts, :ai_governance_sessions]

      def self.enqueue(workflow)
        perform_async(workflow.id)
      end

      def perform(workflow_id)
        workflow = Ai::DuoWorkflows::Workflow.find_by_id(workflow_id)
        return unless workflow

        return if workflow.private_messaging_session?

        # On ClickHouse instances the session list reads siphon_duo_workflows_workflows instead.
        unless ::Gitlab::ClickHouse.globally_enabled_for_analytics?
          Ai::DuoWorkflows::SessionArtifact.sync_from_workflow!(workflow)
        end

        Ai::Governance::Session.sync_from_workflow!(workflow)
      end
    end
  end
end
