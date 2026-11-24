# frozen_string_literal: true

module EE
  module MergeRequestsHelper
    extend ::Gitlab::Utils::Override

    override :summarize_new_merge_request_disabled_reason
    def summarize_new_merge_request_disabled_reason(merge_request)
      source_head_sha = merge_request.source_branch_sha
      target_head_sha = merge_request.target_branch_sha

      if source_head_sha.nil?
        s_('NewMergeRequest|Source branch not available')
      elsif target_head_sha.nil?
        s_('NewMergeRequest|Target branch not available')
      elsif !merge_request.has_diffs?
        s_('NewMergeRequest|No changes between source and target branches')
      else
        super
      end
    end

    override :review_bar_data
    def review_bar_data(merge_request, user)
      super.merge({ can_summarize: Ability.allowed?(user, :access_summarize_review, merge_request).to_s })
    end

    override :ai_overview_available?
    def ai_overview_available?
      ::Feature.enabled?(:mr_ai_overview, current_user, type: :wip)
    end

    override :ai_overview_enabled?
    def ai_overview_enabled?
      ai_overview_available? && cookies[:mr_ai_overview_enabled] == 'true'
    end

    override :identity_verification_alert_data
    def identity_verification_alert_data(merge_request)
      {
        identity_verification_required: show_iv_alert_for_mr?(merge_request).to_s,
        identity_verification_path: identity_verification_path
      }
    end

    override :project_merge_requests_list_data
    def project_merge_requests_list_data(project, current_user)
      super.merge({
        merge_trains_path: merge_trains_available?(project) && can?(current_user, :read_merge_train, project) ? project_merge_trains_path(project) : nil,
        has_scoped_labels_feature: project.licensed_feature_available?(:scoped_labels).to_s
      })
    end

    override :group_merge_requests_list_data
    def group_merge_requests_list_data(group, current_user)
      super.merge({
        has_scoped_labels_feature: group.licensed_feature_available?(:scoped_labels).to_s
      })
    end

    override :merge_request_dashboard_search_data
    def merge_request_dashboard_search_data
      super.merge({
        has_scoped_labels_feature: License.feature_available?(:scoped_labels).to_s
      })
    end

    override :code_dropdown_data
    def code_dropdown_data(merge_request)
      return super unless ::License.feature_available?(:remote_development)

      super.merge(
        workspace_path: workspace_path_with_params(
          project_path: merge_request.source_project.full_path,
          ref: merge_request.source_branch
        ),
        workspace_event_label: "#{controller_name}:#{action_name}"
      )
    end

    def can_resolve_with_ai?(merge_request)
      merge_request.can_resolve_with_ai?(current_user)
    end

    private

    def show_iv_alert_for_mr?(merge_request)
      return false unless current_user
      return false unless current_user == merge_request.author
      return false unless merge_request.project

      !::Users::IdentityVerification::AuthorizeCi.new(user: current_user, project: merge_request.project).user_can_run_jobs?
    end
  end
end
