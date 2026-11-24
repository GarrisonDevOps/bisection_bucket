# frozen_string_literal: true

module Groups
  module Security
    class AgentArtifactsController < Groups::ApplicationController
      include ::Security::AgentArtifactsDownloadable

      feature_category :compliance_management

      private

      def find_session_artifact(id)
        ::Ai::DuoWorkflows::Workflow.find_in_namespace(group, id)
      end

      def ai_governance_sessions_namespace
        group
      end

      def authorize_view_agent_artifacts!
        render_404 unless group.licensed_feature_available?(:group_level_compliance_dashboard) &&
          can?(current_user, :read_agent_artifacts, group)
      end
    end
  end
end
