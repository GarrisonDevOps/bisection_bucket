# frozen_string_literal: true

module Security
  module ProjectTrackedContexts
    class DestroyService
      def initialize(tracked_context:, current_user:)
        @tracked_context = tracked_context
        @current_user = current_user
      end

      def execute
        return default_branch_error if tracked_context.is_default?

        if tracked_context.destroy
          delete_sbom_occurrence_refs_from_elasticsearch
          ServiceResponse.success(payload: { tracked_context: tracked_context })
        else
          ServiceResponse.error(message: tracked_context.errors.full_messages.join(', '))
        end
      end

      private

      attr_reader :tracked_context, :current_user

      def default_branch_error
        ServiceResponse.error(message: 'Cannot untrack default branch')
      end

      def delete_sbom_occurrence_refs_from_elasticsearch
        ::Search::Elastic::DeleteWorker.perform_async(
          'task' => 'delete_tracked_context_sbom_occurrences',
          'project_id' => tracked_context.project_id,
          'security_project_tracked_context_id' => tracked_context.id
        )
      end
    end
  end
end
