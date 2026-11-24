# frozen_string_literal: true

module EE
  module Projects
    module ForkService
      extend ::Gitlab::Utils::Override

      override :stream_audit_event
      def stream_audit_event(forked_project)
        audit_context = {
          name: 'project_fork_operation',
          stream_only: true,
          author: current_user,
          scope: project,
          target: project,
          message: "Forked project to #{forked_project.full_path}"
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
      override :allowed_fork?
      def allowed_fork?
        result = ::Users::Abuse::ProjectsDownloadBanCheckService.execute(current_user, project)
        return false if result.error?

        super
      end
      override :link_existing_project
      def link_existing_project(fork_to_project)
        source_root = project.root_ancestor
        target_root = fork_to_project.root_ancestor

        if target_root.is_a?(Group) && target_root.prevent_forking_outside_group? && source_root != target_root
          return ServiceResponse.error(
            message: _('Target group prevents forks that point outside this group'),
            reason: :outside_group
          )
        end

        super
      end
    end
  end
end
