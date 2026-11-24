# frozen_string_literal: true

module EE
  module MergeRequestWidgetEntity
    include ::API::Helpers::RelatedResourcesHelpers
    extend ActiveSupport::Concern

    prepended do
      expose :require_password_to_approve?, as: :require_password_to_approve

      expose :merge_request_approvers_available do |merge_request|
        merge_request.target_project.licensed_feature_available?(:merge_request_approvers)
      end

      expose :multiple_approval_rules_available do |merge_request|
        merge_request.target_project.multiple_approval_rules_available?
      end

      expose :risk_classification_available do |merge_request|
        ::Feature.enabled?(:show_duo_mr_risk_classification_widget, current_user) &&
          ::Gitlab::Duo::RiskAssessment.available?(merge_request.target_project)
      end

      expose :browser_performance, if: ->(mr, _) { head_pipeline_downloadable_path_for_report_type(:browser_performance) } do
        expose :degradation_threshold do |merge_request|
          merge_request.head_pipeline&.present(current_user: current_user)
            &.degradation_threshold(:browser_performance)
        end

        expose :head_path do |merge_request|
          head_pipeline_downloadable_path_for_report_type(:browser_performance)
        end

        expose :base_path do |merge_request|
          base_pipeline_downloadable_path_for_report_type(:browser_performance)
        end
      end

      expose :load_performance, if: ->(mr, _) { head_pipeline_downloadable_path_for_report_type(:load_performance) } do
        expose :head_path do |merge_request|
          head_pipeline_downloadable_path_for_report_type(:load_performance)
        end

        expose :base_path do |merge_request|
          base_pipeline_downloadable_path_for_report_type(:load_performance)
        end
      end

      expose :license_scanning, if: ->(mr, _) { can?(current_user, :read_licenses, mr.target_project) } do
        expose :can_manage_licenses do |merge_request|
          can?(current_user, :admin_software_license_policy, merge_request)
        end

        expose :full_report_path, if: ->(mr, _) { mr.head_pipeline } do |merge_request|
          licenses_project_pipeline_path(
            merge_request.head_pipeline.project,
            merge_request.head_pipeline
          )
        end
      end

      expose :metrics_reports_path, if: ->(mr, _) { mr.has_metrics_reports? } do |merge_request|
        metrics_reports_project_merge_request_path(merge_request.project, merge_request, format: :json)
      end

      expose :pipeline_id, if: ->(mr, _) { mr.head_pipeline } do |merge_request|
        merge_request.head_pipeline.id
      end

      expose :pipeline_iid, if: ->(mr, _) { mr.head_pipeline } do |merge_request|
        merge_request.head_pipeline.iid
      end

      expose :can_read_vulnerabilities do |merge_request|
        can?(current_user, :read_security_resource, merge_request.project)
      end

      expose :can_read_vulnerability_feedback do |merge_request|
        can?(current_user, :read_vulnerability_feedback, merge_request.project)
      end

      expose :create_vulnerability_feedback_issue_path do |merge_request|
        presenter(merge_request).create_vulnerability_feedback_issue_path(merge_request.project)
      end

      expose :create_vulnerability_feedback_merge_request_path do |merge_request|
        presenter(merge_request).create_vulnerability_feedback_merge_request_path(merge_request.project)
      end

      expose :create_vulnerability_feedback_dismissal_path do |merge_request|
        presenter(merge_request).create_vulnerability_feedback_dismissal_path(merge_request.project)
      end

      expose :discover_project_security_path do |merge_request|
        presenter(merge_request).discover_project_security_path
      end

      expose :approval_feature_available?, as: :has_approvals_available

      expose :api_approval_settings_path do |merge_request|
        presenter(merge_request).api_approval_settings_path
      end

      expose :merge_immediately_docs_path do |merge_request|
        presenter(merge_request).merge_immediately_docs_path
      end

      expose :saml_approval_path do |merge_request|
        presenter(merge_request).saml_approval_path
      end

      expose :require_saml_auth_to_approve do |merge_request|
        presenter(merge_request).require_saml_auth_to_approve
      end
    end
  end
end
