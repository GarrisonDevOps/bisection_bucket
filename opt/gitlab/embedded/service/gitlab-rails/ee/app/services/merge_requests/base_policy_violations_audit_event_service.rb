# frozen_string_literal: true

module MergeRequests
  class BasePolicyViolationsAuditEventService
    include Gitlab::Utils::StrongMemoize

    def initialize(merge_request)
      @merge_request = merge_request
    end

    def execute
      return unless eligible_to_run?
      return if violations.blank?

      grouped_violations.each do |security_policy, violations|
        audit_context = {
          name: audit_event_name,
          author: audit_author,
          scope: security_policy.security_policy_management_project,
          target: security_policy,
          message: audit_message,
          additional_details: audit_details(violations)
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end

    private

    attr_reader :merge_request

    def audit_details(violations)
      {
        merge_request_title: merge_request.title,
        merge_request_id: merge_request.id,
        merge_request_iid: merge_request.iid,
        source_branch: merge_request.source_branch,
        target_branch: merge_request.target_branch,
        project_id: merge_request_project.id,
        project_name: merge_request_project.name,
        project_full_path: merge_request_project.full_path,
        policy_violations: violations.map do |violation|
          {
            approval_policy_rule_id: violation.approval_policy_rule_id,
            violation_status: violation.status,
            violation_data: violation.violation_data
          }
        end
      }
    end

    def merge_request_reference
      "#{merge_request_project.full_path}!#{merge_request.iid}"
    end

    def violations
      merge_request.scan_result_policy_violations.including_security_policies
    end
    strong_memoize_attr :violations

    def grouped_violations
      violations
      .select(&:security_policy)
      .group_by(&:security_policy)
    end
    strong_memoize_attr :grouped_violations

    def merge_request_project
      merge_request.project
    end
    strong_memoize_attr :merge_request_project

    def unknown_user
      Gitlab::Audit::DeletedAuthor.new(id: Gitlab::Audit::NullAuthor::UNKNOWN_USER_AUTHOR_ID, name: 'Unknown User')
    end

    def eligible_to_run?
      raise NoMethodError, "#{self.class.name} must implement #{__method__}"
    end

    def audit_event_name
      raise NoMethodError, "#{self.class.name} must implement #{__method__}"
    end

    def audit_message
      raise NoMethodError, "#{self.class.name} must implement #{__method__}"
    end

    def audit_author
      raise NoMethodError, "#{self.class.name} must implement #{__method__}"
    end
  end
end
