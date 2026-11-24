# frozen_string_literal: true

module EE
  module Organizations
    module SoftDeleteService
      extend ::Gitlab::Utils::Override

      private

      override :log_event
      def log_event
        super

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def audit_context
        {
          name: 'organization_soft_deleted',
          author: current_user,
          scope: ::Gitlab::Audit::InstanceScope.new,
          target: organization,
          message: "Soft deleted organization '#{organization.name}'"
        }
      end
    end
  end
end
