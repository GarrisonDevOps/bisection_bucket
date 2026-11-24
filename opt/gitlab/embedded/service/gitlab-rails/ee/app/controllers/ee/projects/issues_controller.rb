# frozen_string_literal: true

module EE
  module Projects
    module IssuesController
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      EE_ISSUES_EXCEPT_ACTIONS = [:delete_description_version, :description_diff].freeze

      prepended do
        include DescriptionDiffActions
        include GeoInstrumentation
        include ::Observability::ObservabilityIssuesHelper
        include EpicParamActions

        before_action :disable_query_limiting_ee, only: [:update, :bulk_update]

        before_action only: [:new, :create, :show] do
          if can?(current_user, :generate_description, project)
            push_licensed_feature(:generate_description, project)
          end
        end

        before_action only: :new do
          if can?(current_user, :read_observability, project)
            @observability_values = gather_observability_values(
              params.permit(:observability_metric_details, :observability_log_details, :observability_trace_details)
            )
          end
        end

        before_action only: :show do
          push_licensed_feature(:escalation_policies, project)

          if can?(current_user, :summarize_comments, issue)
            push_licensed_feature(:summarize_comments, project)
          end

          push_frontend_ability(ability: :summarize_comments, resource: issue, user: current_user)
          push_frontend_feature_flag(:agent_presence_consolidation, project&.root_ancestor)
        end

        before_action :redirect_if_test_case, only: [:show]

        before_action only: [:index, :show] do
          push_force_frontend_feature_flag(:okrs_mvc, !!project&.okrs_mvc_feature_flag_enabled?)
          push_licensed_feature(:okrs, project)
        end

        feature_category :team_planning, [:delete_description_version, :description_diff]
        urgency :low, [:delete_description_version, :description_diff]
      end

      private

      override :work_item_redirect_except_actions
      def work_item_redirect_except_actions
        super + EE_ISSUES_EXCEPT_ACTIONS
      end

      override :finder_options
      def finder_options
        options = super

        options.delete(:weight) unless project.feature_available?(:issue_weights)

        if options[:custom_field]
          options[:custom_field] = options[:custom_field].to_h.map do |id, option_ids|
            { custom_field_id: id, selected_option_ids: Array(option_ids) }
          end
        end

        options
      end

      override :redirect_if_epic_params
      def redirect_if_epic_params
        # To handle legacy urls with epic filters, translate these to the parent filter equivalents and redirect
        return unless has_epic_filter?

        redirect_to project_issues_path(project, params: convert_epic_params)

        true
      end

      def disable_query_limiting_ee
        ::Gitlab::QueryLimiting.disable!('https://gitlab.com/gitlab-org/gitlab/-/issues/438295', new_threshold: 220)
      end

      def create_vulnerability_issue_feedback(issue)
        return unless issue.persisted? && vulnerability

        result = VulnerabilityFeedback::CreateService.new(
          issue.project,
          current_user,
          vulnerability_issue_feedback_params(issue, vulnerability)
        ).execute
        show_error = result[:message].errors.any?

        flash[:raw] = render_vulnerability_link_alert.html_safe if show_error
      end

      def vulnerability_issue_feedback_params(issue, vulnerability)
        feedback_params = {
          issue: issue,
          feedback_type: 'issue',
          category: vulnerability.report_type,
          finding_uuid: vulnerability.finding_uuid,
          vulnerability_data: vulnerability.as_json
        }

        feedback_params[:vulnerability_data][:vulnerability_id] = vulnerability.id

        feedback_params
      end

      def render_vulnerability_link_alert
        render_to_string(
          partial: 'vulnerabilities/unable_to_link_vulnerability',
          formats: :html,
          locals: {
            vulnerability_link: vulnerability_path(vulnerability)
          }
        )
      end

      def redirect_if_test_case
        return unless issue.work_item_type&.test_case?

        redirect_to project_quality_test_case_path(project, issue)
      end

      override :work_items_redirect_params
      def work_items_redirect_params(params)
        return super(convert_epic_params) if has_epic_filter?

        super
      end
    end
  end
end
