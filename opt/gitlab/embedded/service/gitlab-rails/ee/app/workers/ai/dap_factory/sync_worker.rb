# frozen_string_literal: true

module Ai
  module DapFactory
    # rubocop:disable Sidekiq/EnforceDatabaseHealthSignalDeferral -- Sync touches few rows on ai_flow_triggers
    class SyncWorker
      include ApplicationWorker
      include ::Gitlab::Loggable

      LeaseTakenError = Class.new(::Gitlab::SidekiqMiddleware::RetryError)
      LEASE_RETRY_DELAY = 30.seconds

      data_consistency :sticky
      urgency :low
      worker_has_external_dependencies!

      sidekiq_retry_in do |_count, exception|
        LEASE_RETRY_DELAY.to_i if exception.is_a?(LeaseTakenError)
      end

      deduplicate :until_executed
      idempotent!

      feature_category :dap_triggers

      def perform(project_id, user_id, oldrev, newrev, _ref)
        project = Project.find_by_id(project_id)
        return unless project
        return unless ::Gitlab::Ai::SoftwareFactory.enabled?(project)
        return unless configuration_modified?(project, oldrev, newrev)

        user = User.find_by_id(user_id)
        return unless user

        result = SyncService.new(project: project, current_user: user).execute
        return if result.success?

        raise LeaseTakenError, result.message if result.reason == :lease_taken

        log_failure(project, result)
      end

      private

      # Reading the file's blob at both commits is one Gitaly call for one path, so its cost does not
      # grow with the size of the push. It also raises where modified_paths rescues a Gitaly failure
      # and returns nothing, which would skip a real change instead of retrying it.
      def configuration_modified?(project, oldrev, newrev)
        return false if ::Gitlab::Git.blank_ref?(newrev)
        return true if ::Gitlab::Git.blank_ref?(oldrev)

        path = ::Gitlab::Ai::DapFactory::Configuration::PATH
        blobs = project.repository.blobs_at([[oldrev, path], [newrev, path]], blob_size_limit: 0)
          .to_h { |blob| [blob.commit_id, blob.id] }

        blobs[oldrev] != blobs[newrev]
      end

      def log_failure(project, result)
        ::Gitlab::AppJsonLogger.warn(
          build_structured_payload_labkit(
            Labkit::Fields::LOG_MESSAGE => "DAP Factory Sync did not apply the configuration: #{result.reason}",
            Labkit::Fields::GL_PROJECT_ID => project.id,
            Labkit::Fields::ERROR_MESSAGE => result.message
          )
        )
      end
    end
    # rubocop:enable Sidekiq/EnforceDatabaseHealthSignalDeferral
  end
end
