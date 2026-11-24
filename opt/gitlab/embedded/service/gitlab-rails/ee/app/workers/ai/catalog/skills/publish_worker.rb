# frozen_string_literal: true

module Ai
  module Catalog
    module Skills
      class PublishWorker
        include ApplicationWorker
        include ::Gitlab::Loggable

        LeaseTakenError = Class.new(::Gitlab::SidekiqMiddleware::RetryError)

        data_consistency :sticky
        urgency :low

        # nil falls through to Sidekiq's own exponential backoff.
        sidekiq_retry_in do |_count, exception|
          30 if exception.is_a?(LeaseTakenError)
        end

        defer_on_database_health_signal :gitlab_main,
          [:ai_catalog_items, :ai_catalog_item_versions], 5.minutes

        # Only catches a redelivery of the same push: the key is the full argument list, and
        # consecutive pushes carry different revs. Racing pushes are handled by LeaseTakenError.
        deduplicate :until_executed
        idempotent!

        feature_category :ai_catalog_creation

        def perform(project_id, oldrev, newrev, ref)
          project = Project.find_by_id(project_id)
          return unless project
          # Rechecked here because a licence can lapse between the push and this job running.
          return unless ::Ai::Catalog.available_for_project?(project)
          return unless skill_file_modified?(project, oldrev, newrev, ref)

          result = ::Ai::Catalog::Skills::PublishService.new(project: project).execute
          return if result.success?

          raise LeaseTakenError, result.message if result.reason == :lease_taken

          log_failure(project, result)
        end

        private

        # modified_paths raises unless the branch was updated.
        def skill_file_modified?(project, oldrev, newrev, ref)
          push = ::Gitlab::Git::Push.new(project, oldrev, newrev, ref)
          return false unless push.branch_updated?

          push.modified_paths.any? { |path| ::Gitlab::Ai::Catalog::Skills::Path::REGEX.match?(path) }
        end

        def log_failure(project, result)
          ::Gitlab::AppJsonLogger.warn(
            build_structured_payload_labkit(
              Labkit::Fields::LOG_MESSAGE => 'Failed to publish skills after a push',
              Labkit::Fields::GL_PROJECT_ID => project.id,
              reason: result.reason,
              Labkit::Fields::ADDITIONAL_DETAILS => result.message
            )
          )
        end
      end
    end
  end
end
