# frozen_string_literal: true

module EE
  module Organizations
    module HardDeleteService
      extend ::Gitlab::Utils::Override

      private

      override :before_organization_destroy
      def before_organization_destroy
        super

        ::Workforce::Hierarchy.delete_for_tenant(organization: organization)
      end

      override :log_event
      def log_event(organization_path)
        super

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def audit_context
        {
          name: 'organization_hard_deleted',
          author: current_user,
          scope: ::Gitlab::Audit::InstanceScope.new,
          target: organization,
          message: "Hard deleted organization '#{organization.name}'"
        }
      end
    end
  end
end
