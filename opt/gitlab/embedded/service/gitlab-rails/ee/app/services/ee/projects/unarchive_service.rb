# frozen_string_literal: true

module EE
  module Projects
    module UnarchiveService
      extend ::Gitlab::Utils::Override

      private

      override :after_unarchive
      def after_unarchive
        super

        log_audit_event
      end

      def log_audit_event
        audit_context = {
          name: 'project_unarchived',
          author: current_user,
          target: project,
          scope: project,
          message: 'Project unarchived'
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
