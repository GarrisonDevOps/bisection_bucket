# frozen_string_literal: true

module MergeRequests
  module StatusCheckResponses
    class AuditUpdateResponseService
      def initialize(status_check_response, current_user = nil)
        @status_check_response = status_check_response
        @current_user = current_user
      end

      def execute
        log_audit_event
      end

      private

      attr_reader :status_check_response, :current_user

      def log_audit_event
        ::Gitlab::Audit::Auditor.audit(
          name: 'status_check_response_update',
          author: author,
          scope: external_status_check.project,
          target: merge_request,
          message: "Updated response for status check #{external_status_check.name} to #{status_check_response.status}",
          additional_details: {
            external_status_check_id: external_status_check.id,
            external_status_check_name: external_status_check.name,
            status: status_check_response.status,
            sha: status_check_response.sha,
            merge_request_id: merge_request.id,
            merge_request_iid: merge_request.iid
          }
        )
      end

      def author
        current_user || ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)')
      end

      def external_status_check
        status_check_response.external_status_check
      end

      def merge_request
        status_check_response.merge_request
      end
    end
  end
end
