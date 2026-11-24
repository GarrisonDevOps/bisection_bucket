# frozen_string_literal: true

module EE
  module ContainerRegistry
    module DeleteContainerRepositoryWorker
      extend ::Gitlab::Utils::Override

      private

      override :audit_event
      def audit_event(repository)
        audit_context = {
          name: "container_repository_deleted",
          author: ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
          scope: repository.project,
          target: repository,
          message: "Container repository #{repository.id} deleted by worker"
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
