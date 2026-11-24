# frozen_string_literal: true

module Security
  module Policies
    class DismissalPreserveWorker
      include Gitlab::EventStore::Subscriber

      data_consistency :sticky
      idempotent!

      defer_on_database_health_signal :gitlab_main, [:project_audit_events], 1.minute

      # Audit stream to external destination with HTTP request if configured
      worker_has_external_dependencies!

      feature_category :security_policy_management

      def handle_event(event)
        dismissal = Security::PolicyDismissal.find_by_id(event.data[:security_policy_dismissal_id])

        return unless dismissal

        # security_policy is optional on PolicyDismissal and the policy may have
        # been deleted between dismissal creation and this audit event being
        # processed. AuditEvents::BuildService requires `target` to be present
        # and raises MissingAttributeError otherwise, so bail out here.
        return unless dismissal.security_policy
        return unless dismissal.merge_request

        audit_context = {
          name: 'merge_request_merged_with_dismissed_security_policy',
          author: dismissal.user,
          scope: dismissal.project,
          target: dismissal.security_policy,
          message: "Merge request #{dismissal.merge_request.to_reference} was merged with violated security policy.",
          additional_details: {
            policy_name: dismissal.security_policy.name,
            dismissal_types: dismissal.dismissal_types.map { |t| Security::PolicyDismissal.dismissal_type_name(t) },
            dismissal_comment: dismissal.comment,
            merge_request_iid: dismissal.merge_request.iid,
            merge_request_title: dismissal.merge_request.title,
            project_full_path: dismissal.project.full_path
          }
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
