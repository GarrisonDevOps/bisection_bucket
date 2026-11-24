# frozen_string_literal: true

module EE
  module Projects
    module RepositoriesController
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      private

      override :check_archive_download_throttling!
      def check_archive_download_throttling!
        result = ::Users::Abuse::ProjectsDownloadBanCheckService.execute(current_user, project)
        if result.error?
          render(plain: _('You are not allowed to download code from this project.'), status: :forbidden)
          return
        end

        super
      end

      override :log_archive_audit_event
      def log_archive_audit_event
        project = repository.project
        audit_event_type = project.public? ? 'public_repository_download_operation' : 'repository_download_operation'
        audit_context = {
          name: audit_event_type,
          author: current_user || ::Gitlab::Audit::UnauthenticatedAuthor.new,
          scope: project,
          target: project,
          message: 'Repository Download Started',
          ip_address: request.remote_ip
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
