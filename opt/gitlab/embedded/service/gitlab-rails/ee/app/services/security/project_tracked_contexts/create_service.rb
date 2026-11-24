# frozen_string_literal: true

module Security
  module ProjectTrackedContexts
    class CreateService
      include LoggableCreation

      def initialize(project:, context_name:, context_type:, is_default: false)
        @project = project
        @context_name = context_name
        @context_type = context_type
        @is_default = is_default
      end

      def execute
        return ref_not_found_error unless ref_exists_in_repository?

        create_tracked_context
      end

      private

      attr_reader :project, :context_name, :context_type, :is_default

      def ref_exists_in_repository?
        return false unless project.repository_exists?

        case context_type.to_sym
        when :branch
          project.repository.branch_exists?(context_name)
        when :tag
          project.repository.tag_exists?(context_name)
        end
      end

      def create_tracked_context
        tracked_context = Security::ProjectTrackedContext.create(
          project: project,
          context_name: context_name,
          context_type: context_type.to_sym,
          is_default: is_default,
          state: Security::ProjectTrackedContext::STATES[:tracked],
          uuid_version: Security::ProjectTrackedContext::CONTEXT_AWARE_UUID_VERSION
        )

        if tracked_context.persisted?
          log_created(tracked_context)

          ServiceResponse.success(payload: { tracked_context: tracked_context })
        else
          ServiceResponse.error(message: tracked_context.errors.full_messages.join(', '))
        end
      end

      def ref_not_found_error
        ServiceResponse.error(message: 'Ref does not exist in repository')
      end
    end
  end
end
