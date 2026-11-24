# frozen_string_literal: true

module EE
  module Projects
    module InactiveProjectsDeletionCronWorker
      extend ::Gitlab::Utils::Override

      override :log_audit_event
      def log_audit_event(project, user)
        audit_context = {
          name: 'inactive_project_scheduled_for_deletion',
          author: user,
          scope: project,
          target: project,
          message: "Project is scheduled to be deleted on #{deletion_date} due to inactivity."
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
