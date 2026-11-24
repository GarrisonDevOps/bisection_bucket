# frozen_string_literal: true

module Security
  module ProjectTrackedContexts
    class CreateOrUpdateDefaultTrackedContextWorker
      include ApplicationWorker
      prepend ::Geo::SkipSecondary
      include Gitlab::EventStore::Subscriber

      data_consistency :sticky
      feature_category :vulnerability_management
      idempotent!

      # The worker is idempotent, but we want to ensure that if multiple events are triggered
      # for the same project (e.g., project created and then default branch changed),
      # the latest event always updates the tracked context.
      # By rescheduling once, we ensure that the last event's job will be executed.
      deduplicate :until_executed, if_deduplicated: :reschedule_once

      # Ensures deduplication across all event types based on project_id
      # EventStore subscriptions filter for container_type == 'Project' only
      def self.idempotency_arguments(arguments)
        event_type, data = arguments

        # Extract project_id based on event type
        project_id = case event_type
                     when 'Projects::ProjectCreatedEvent'
                       data["project_id"]
                     when 'Repositories::DefaultBranchChangedEvent', 'Repositories::RepositoryCreatedEvent'
                       data["container_id"]
                     end

        [project_id]
      end

      def handle_event(event)
        project_id = case event
                     when ::Projects::ProjectCreatedEvent
                       event.data[:project_id]
                     when ::Repositories::DefaultBranchChangedEvent, ::Repositories::RepositoryCreatedEvent
                       event.data[:container_id]
                     end

        return unless project_id

        Project.find_by_id(project_id).try do |project|
          result = ProjectTrackedContexts::FindOrCreateService.project_default_branch(project).execute!

          log_error(project, result.errors) if result.error?
        end
      end

      private

      def log_error(project, errors)
        Gitlab::AppLogger.warn(
          message: "Failed to create default tracked context for project: #{errors.join(',')}",
          project_id: project.id,
          project_path: project.full_path
        )
      end
    end
  end
end
