# frozen_string_literal: true

module Security
  module ProjectTrackedContexts
    # Shared by the services that create `Security::ProjectTrackedContext` records, so the
    # payload stays identical across the user-initiated and the automatic creation paths.
    # `class_name` in the payload identifies which of the two did the creating.
    module LoggableCreation
      include Gitlab::Loggable

      private

      def log_created(tracked_context)
        Gitlab::AppJsonLogger.info(
          build_structured_payload_labkit(
            Labkit::Fields::LOG_MESSAGE => 'Security tracked context created',
            Labkit::Fields::GL_PROJECT_ID => tracked_context.project_id,
            tracked_context_id: tracked_context.id,
            context_name: tracked_context.context_name,
            context_type: tracked_context.context_type,
            is_default: tracked_context.is_default?
          )
        )
      end
    end
  end
end
