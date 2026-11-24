# frozen_string_literal: true

module Security
  module Findings
    class CreateJiraIssueFormUrlService < ::BaseProjectService
      include Gitlab::Utils::StrongMemoize
      include VulnerabilitiesHelper

      def execute
        return error(vulnerability_response[:message]) if vulnerability_response.error?

        jira_issue_form_url
      end

      private

      def jira_issue_form_url
        jira_url = create_jira_issue_url_for(vulnerability)

        return error('Jira integration is not configured.') unless jira_url

        ServiceResponse.success(payload: { record: jira_url })
      end

      def vulnerability_response
        Vulnerabilities::FindOrCreateFromSecurityFindingService.new(
          project: @project,
          current_user: @current_user,
          params: params,
          present_on_default_branch: false,
          state: 'detected').execute
      end
      strong_memoize_attr :vulnerability_response

      def vulnerability
        vulnerability_response.payload[:vulnerability]
      end

      def error(message)
        ServiceResponse.error(message: message)
      end
    end
  end
end
