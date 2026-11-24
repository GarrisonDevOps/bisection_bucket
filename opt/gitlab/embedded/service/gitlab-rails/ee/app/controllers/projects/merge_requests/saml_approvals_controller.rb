# frozen_string_literal: true

module Projects
  module MergeRequests
    class SamlApprovalsController < Projects::ApplicationController
      feature_category :code_review_workflow

      def create
        return render_404 unless merge_request
        return render_404 unless approval_requires_saml_auth?

        if approval_service.execute(merge_request).success?
          flash[:notice] = _("Approved")
        else
          flash[:alert] = _("Approval rejected.")
        end

        redirect_to(
          namespace_project_merge_request_path(
            id: merge_request_iid,
            project_id: merge_request.project,
            namespace_id: merge_request.project.namespace
          )
        )
      end

      private

      def approval_service
        @approval_service ||= ::MergeRequests::ApprovalService
          .new(project: project, current_user: current_user)
      end

      def approval_requires_saml_auth?
        approval_service.approval_requires_saml_auth?
      end

      def project_id
        project.id
      end

      def group_id
        project.group.id
      end

      def merge_request_iid
        params.permit(:id).fetch(:id)
      end

      def merge_request
        @merge_request ||= MergeRequestsFinder.new(
          current_user,
          group_id: group_id,
          project_id: project_id,
          iids: [merge_request_iid]
        ).execute&.first
      end
    end
  end
end
