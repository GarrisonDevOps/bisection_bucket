# frozen_string_literal: true

module MergeRequests
  class PolicyViolationsDetectedAuditEventService < BasePolicyViolationsAuditEventService
    private

    def eligible_to_run?
      violations.running.none?
    end

    def audit_event_name
      'security_policy_violations_detected'
    end

    def audit_message
      "Security policy violation(s) is detected in merge request (#{merge_request_reference})"
    end

    def audit_author
      merge_request.author || unknown_user
    end
  end
end
