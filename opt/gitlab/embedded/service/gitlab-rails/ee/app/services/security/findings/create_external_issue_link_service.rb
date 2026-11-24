# frozen_string_literal: true

module Security
  module Findings
    class CreateExternalIssueLinkService < ::BaseProjectService
      include Gitlab::Utils::StrongMemoize

      def execute
        return error(vulnerability_response[:message]) if vulnerability_response.error?

        return error(external_issue_link_response[:message]) if external_issue_link_response.error?

        success
      end

      private

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

      def external_issue_link_response
        ::VulnerabilityExternalIssueLinks::CreateService.new(
          @current_user,
          vulnerability,
          params[:external_tracker],
          link_type: params[:link_type]).execute
      end
      strong_memoize_attr :external_issue_link_response

      def external_issue_link
        external_issue_link_response.payload[:record]
      end

      def error(message)
        ServiceResponse.error(message: message)
      end

      def success
        ServiceResponse.success(payload: { record: external_issue_link })
      end
    end
  end
end
