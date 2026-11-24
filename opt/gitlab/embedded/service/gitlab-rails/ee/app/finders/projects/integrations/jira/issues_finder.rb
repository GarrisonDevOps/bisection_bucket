# frozen_string_literal: true

module Projects
  module Integrations
    module Jira
      class IssuesFinder
        Error = Class.new(StandardError)
        IntegrationError = Class.new(Error)
        RequestError = Class.new(Error)

        attr_reader :issues, :per_page, :next_page_token, :is_last, :total_count

        class << self
          def valid_params
            @valid_params ||= %i[page next_page_token per_page search state status author_username assignee_username project]
            # to permit array params you need to init them to an empty array
            @valid_params << { labels: [], vulnerability_ids: [], issue_ids: [] }
          end
        end

        def initialize(project, params = {})
          @project = project
          @jira_integration = project.jira_integration
          @params = params.merge(map_sort_values(params[:sort]))
          set_pagination
        end

        def execute
          return [] unless project.jira_issues_integration_available?

          raise IntegrationError, _('Jira service not configured.') unless jira_integration&.active?

          if params[:vulnerability_ids].present?
            project_keys = jira_integration.project_key

            raise IntegrationError, _('Jira project key is not configured.') if project_keys.blank?
          else
            return [] unless project_keys_allowed?

            project_keys = params[:project].presence || jira_integration.project_keys_as_string
          end

          fetch_issues(project_keys)
        end

        private

        attr_reader :project, :jira_integration, :page_token, :page, :params

        # rubocop: disable CodeReuse/ServiceClass
        def fetch_issues(project_keys)
          jql = ::Jira::JqlBuilderService.new(project_keys, params).execute
          jira_service_class = jira_cloud? ? ::Jira::Requests::Issues::CloudListService : ::Jira::Requests::Issues::ServerListService

          service_params = { jql: jql, next_page_token: page_token, page: page, per_page: per_page }
          service_params[:reconcile_issue_ids] = reconcile_issue_ids if jira_cloud?

          response = jira_service_class.new(jira_integration, service_params).execute

          raise RequestError, response.message if response.error?

          @next_page_token = response.payload[:next_page_token] if jira_cloud?
          @is_last = response.payload[:is_last]
          @total_count = response.payload[:total_count] unless jira_cloud?
          @issues = response.payload[:issues]
        end
        # rubocop: enable CodeReuse/ServiceClass

        def reconcile_issue_ids
          return [] if params[:vulnerability_ids].blank?

          Vulnerabilities::ExternalIssueLink.jira_issue_keys_for_vulnerabilities(params[:vulnerability_ids])
        end

        def jira_cloud?
          jira_integration.data_fields.deployment_cloud?
        end

        def map_sort_values(sort)
          case sort
          when 'created_date', 'created_desc'
            { sort: 'created', sort_direction: 'DESC' }
          when 'created_asc'
            { sort: 'created', sort_direction: 'ASC' }
          when 'updated_desc'
            { sort: 'updated', sort_direction: 'DESC' }
          when 'updated_asc'
            { sort: 'updated', sort_direction: 'ASC' }
          else
            { sort: ::Jira::JqlBuilderService::DEFAULT_SORT, sort_direction: ::Jira::JqlBuilderService::DEFAULT_SORT_DIRECTION }
          end
        end

        def set_pagination
          @page_token = params[:next_page_token]
          @page = (params[:page].presence || 1).to_i unless jira_cloud?
          @per_page = (params[:per_page].presence || ::Jira::Requests::Issues::ListService::PER_PAGE).to_i
        end

        def project_keys_allowed?
          return true if jira_integration.project_keys.blank? || params[:project].blank?

          jira_integration.project_keys.include?(params[:project])
        end
      end
    end
  end
end
