# frozen_string_literal: true

module MergeRequests
  class PolicyViolationsResolvedAuditEventService
    def initialize(merge_request)
      @merge_request = merge_request
    end

    def execute
      return if merge_request.scan_result_policy_violations.any?

      ::Gitlab::Audit::Auditor.audit(audit_context)
    end

    private

    attr_reader :merge_request

    def target_project
      @_target_project ||= merge_request.project
    end

    def audit_context
      {
        name: 'security_policy_violations_resolved',
        message: "All merge request approval policy violation(s) resolved " \
          "in merge request with title '#{merge_request.title}'",
        author: merge_request.author,
        scope: target_project,
        target: merge_request,
        additional_details: additional_details
      }
    end

    def additional_details
      {
        merge_request_title: merge_request.title,
        merge_request_id: merge_request.id,
        merge_request_iid: merge_request.iid,
        source_branch: merge_request.source_branch,
        target_branch: merge_request.target_branch,
        project_id: target_project.id,
        project_name: target_project.name,
        project_full_path: target_project.full_path
      }
    end
  end
end
