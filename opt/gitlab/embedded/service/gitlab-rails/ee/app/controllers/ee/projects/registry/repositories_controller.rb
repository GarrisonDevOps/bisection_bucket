# frozen_string_literal: true

module EE
  module Projects
    module Registry
      module RepositoriesController
        extend ::Gitlab::Utils::Override

        override :destroy
        def destroy
          super

          audit_destroy_marked_event
        end

        private

        def audit_destroy_marked_event
          message = "Marked container repository #{image.id} for deletion"
          audit_context = {
            name: 'container_repository_deletion_marked',
            author: current_user || ::Gitlab::Audit::UnauthenticatedAuthor.new,
            scope: project,
            target: image,
            message: message
          }
          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end
