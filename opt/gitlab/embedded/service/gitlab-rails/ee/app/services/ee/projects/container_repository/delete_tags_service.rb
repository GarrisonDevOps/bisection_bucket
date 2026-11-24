# frozen_string_literal: true

module EE
  module Projects
    module ContainerRepository
      module DeleteTagsService
        extend ::Gitlab::Utils::Override

        override :execute
        def execute(container_repository)
          result = super(container_repository)

          audit_event(container_repository, params[:tags]) if result[:status] == :success

          result
        end

        private

        def audit_event(repository, tags)
          message = "Container repository tags marked for deletion: #{tags.join(', ')}"

          audit_context = {
            name: "container_repository_tags_deleted",
            author: current_user || ::Gitlab::Audit::UnauthenticatedAuthor.new(name: '(System)'),
            scope: project,
            target: repository,
            message: message
          }
          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end
