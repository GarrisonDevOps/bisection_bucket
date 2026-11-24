# frozen_string_literal: true

module EE
  module Projects
    module ArchiveService
      extend ::Gitlab::Utils::Override

      private

      override :after_archive
      def after_archive
        super

        log_audit_event
      end

      def log_audit_event
        audit_context = {
          name: 'project_archived',
          author: current_user,
          target: project,
          scope: project,
          message: 'Project archived'
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
