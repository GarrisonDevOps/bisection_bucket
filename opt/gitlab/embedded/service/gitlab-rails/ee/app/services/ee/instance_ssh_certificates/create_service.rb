# frozen_string_literal: true

module EE
  module InstanceSshCertificates # rubocop:disable Gitlab/BoundedContexts -- Mirrors the existing InstanceSshCertificate model namespace
    module CreateService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute
        response = super
        log_audit_event(response.payload) if response.success?
        response
      end

      private

      def log_audit_event(certificate)
        audit_context = {
          name: 'create_instance_ssh_certificate',
          author: current_user,
          scope: ::Gitlab::Audit::InstanceScope.new,
          target: certificate,
          target_details: certificate.title,
          message: "Created instance SSH certificate with id #{certificate.id} and title #{certificate.title} " \
            "and fingerprint SHA256:#{certificate.fingerprint}"
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
