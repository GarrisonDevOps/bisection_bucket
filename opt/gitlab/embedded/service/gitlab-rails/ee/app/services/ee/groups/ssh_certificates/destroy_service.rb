# frozen_string_literal: true

module EE
  module Groups
    module SshCertificates
      module DestroyService
        extend ::Gitlab::Utils::Override

        override :execute
        def execute
          response = super
          log_audit_event(response.payload[:ssh_certificate]) if response.success?
          response
        end

        private

        def log_audit_event(ssh_certificate)
          audit_context = {
            name: "delete_ssh_certificate",
            author: current_user,
            scope: group,
            target: ssh_certificate,
            target_details: ssh_certificate.title,
            message: "Deleted SSH certificate with id #{ssh_certificate.id} and title #{ssh_certificate.title}"
          }

          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end
