# frozen_string_literal: true

module EE
  module Mutations
    module ContainerRepositories # rubocop:disable Gitlab/BoundedContexts -- fix in FOSS class
      module Destroy
        extend ::Gitlab::Utils::Override

        private

        override :audit_event
        def audit_event(repository)
          message = "Marked container repository #{repository.id} for deletion"
          context = {
            name: 'container_repository_deletion_marked',
            author: current_user,
            scope: repository.project,
            target: repository,
            message: message
          }

          ::Gitlab::Audit::Auditor.audit(context)
        end
      end
    end
  end
end
