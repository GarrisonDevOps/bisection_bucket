# frozen_string_literal: true

module Projects
  module Integrations
    module Jira
      class IssuesController < Projects::ApplicationController
        include RecordUserLastActivity
        include SortingHelper
        include SortingPreference
        include ProductAnalyticsTracking

        track_event :index,
          name: 'i_ecosystem_jira_service_list_issues',
          action: Integration::SNOWPLOW_EVENT_ACTION,
          label: Integration::SNOWPLOW_EVENT_LABEL,
          destinations: %i[redis_hll snowplow]

        before_action :check_feature_enabled!

        rescue_from ::Projects::Integrations::Jira::IssuesFinder::Error, with: :render_error

        feature_category :team_planning

        def index
          respond_to do |format|
            format.html
            format.json do
              render json: issues_json
            end
          end
        end

        def show
          return render_404 if issue_json.nil?

          respond_to do |format|
            format.html do
              issue_json
            end
            format.json do
              render json: issue_json
            end
          end
        end

        private

        def visitor_id
          current_user&.id
        end

        def issues_json
          if jira_integration.data_fields.deployment_cloud?
            cloud_issues_json
          else
            server_issues_json
          end
        end

        def cloud_issues_json
          # Cloud uses token-based pagination
          issues = finder.execute

          response.headers['X-Per-Page'] = finder.per_page.to_s
          response.headers['X-Next-Page-Token'] = finder.next_page_token unless finder.is_last
          response.headers['X-Is-Last'] = finder.is_last.to_s

          ::Integrations::JiraSerializers::IssueSerializer.new
            .represent(issues, project: project)
        end

        def server_issues_json
          # Server uses offset-based pagination with Kaminari
          jira_issues = Kaminari.paginate_array(
            finder.execute,
            limit: finder.per_page,
            total_count: finder.total_count
          )

          ::Integrations::JiraSerializers::IssueSerializer.new
            .with_pagination(request, response)
            .represent(jira_issues, project: project)
        end

        def issue_json
          @issue_json ||= ::Integrations::JiraSerializers::IssueDetailSerializer.new
            .represent(
              project.jira_integration.find_issue(
                id_param,
                rendered_fields: true,
                restrict_project_key: true
              ),
              current_user: current_user,
              project: project
            )
        end

        def finder
          @finder ||= ::Projects::Integrations::Jira::IssuesFinder.new(project, finder_options)
        end

        def finder_options
          options = { sort: set_sort_order, state: filter_state }

          # Used by view to highlight active option
          @sort = options[:sort]

          finder_params.merge(options).to_h
        end

        def finder_params
          params.permit(::Projects::Integrations::Jira::IssuesFinder.valid_params)
        end

        def id_param
          params.permit(:id)[:id]
        end

        def state_param
          params.permit(:state)[:state]
        end

        def default_state
          'opened'
        end

        def filter_state
          @filter_state ||= state_param.presence || default_state
        end

        def default_sort_order
          if filter_state == 'closed'
            sort_value_recently_updated
          else
            sort_value_created_date
          end
        end

        protected

        def check_feature_enabled!
          render_404 unless project.jira_issues_integration_available? &&
            jira_integration&.active &&
            (jira_integration&.issues_enabled || jira_integration&.vulnerabilities_enabled)
        end

        def jira_integration
          @jira_integration ||= project.jira_integration
        end

        def render_error(exception)
          log_exception(exception)

          render json: { errors: [exception.message] }, status: :bad_request
        end

        def tracking_namespace_source
          project.namespace
        end

        def tracking_project_source
          project
        end
      end
    end
  end
end
