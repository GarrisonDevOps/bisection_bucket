# frozen_string_literal: true

module Projects
  module Security
    class AgentArtifactsController < Projects::ApplicationController
      include ::Security::AgentArtifactsDownloadable

      feature_category :compliance_management

      private

      def find_session_artifact(id)
        ::Ai::DuoWorkflows::Workflow.find_in_project(project, id)
      end

      def ai_governance_sessions_namespace
        project.project_namespace
      end

      def authorize_view_agent_artifacts!
        render_404 unless project.licensed_feature_available?(:project_level_compliance_dashboard) &&
          can?(current_user, :read_agent_artifacts, project)
      end
    end
  end
end
