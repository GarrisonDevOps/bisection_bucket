# frozen_string_literal: true

module Projects
  module Security
    class VulnerabilitiesController < Projects::ApplicationController
      include IssuableActions
      include GovernUsageProjectTracking

      before_action :vulnerability, except: [:new]
      before_action :disable_query_limiting, only: [:show]
      before_action :authorize_admin_vulnerability!, except: [:show, :discussions]
      before_action :authorize_read_vulnerability!, except: [:new]

      before_action do
        push_frontend_feature_flag(:hide_vulnerability_severity_override, project)
        push_frontend_feature_flag(:duo_secret_detection_false_positive, project.root_ancestor, type: :beta)
        push_frontend_feature_flag(:agentic_sast_vr_ui, project.root_ancestor, type: :beta)
        push_frontend_feature_flag(:secrets_manager_pat_rotation, project.root_ancestor, type: :beta)
        push_frontend_feature_flag(:security_ai_flow_feedback, project, type: :wip)
      end

      alias_method :vulnerable, :project

      feature_category :vulnerability_management
      urgency :low
      track_govern_activity 'security_vulnerabilities', :show

      def show
        push_frontend_ability(ability: :resolve_vulnerability_with_ai, resource: vulnerability, user: current_user)
        push_frontend_feature_flag(:dependency_paths, project)

        pipeline = vulnerability.finding.first_finding_pipeline
        @pipeline = pipeline if can?(current_user, :read_pipeline, pipeline)
        @policy_dismissals = policy_dismissals
        @gfm_form = true
      end

      def disable_query_limiting
        Gitlab::QueryLimiting.disable!('https://gitlab.com/gitlab-org/gitlab/-/issues/561234', new_threshold: 120)
      end

      private

      def vulnerability
        @issuable = @noteable = @vulnerability ||= vulnerable.vulnerabilities.find(params.permit(:id)[:id])
      end

      def policy_dismissals
        finding_uuid = vulnerability.vulnerability_finding&.uuid

        return [] if finding_uuid.nil?

        project
          .policy_dismissals
          .including_merge_request_and_user
          .for_security_findings_uuids(finding_uuid)
          .preserved
      end

      alias_method :issuable, :vulnerability
      alias_method :noteable, :vulnerability

      def issue_serializer
        IssueSerializer.new(current_user: current_user)
      end
    end
  end
end
