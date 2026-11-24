# frozen_string_literal: true

module Packages
  module Npm
    class CreateMetadataCacheWorker
      include ApplicationWorker

      data_consistency :sticky

      queue_namespace :package_repositories
      feature_category :package_registry

      deduplicate :until_executed, if_deduplicated: :reschedule_once
      idempotent!

      CONCURRENCY_LIMIT = 80

      # nil falls back to the shard-wide default limit
      concurrency_limit -> {
        CONCURRENCY_LIMIT if Feature.enabled?(:npm_metadata_cache_worker_concurrency_limit, :instance)
      }

      def perform(project_id, package_name)
        project = Project.find_by_id(project_id)

        return unless project

        ::Packages::Npm::CreateMetadataCacheService
          .new(project, package_name)
          .execute
      rescue StandardError => e
        Gitlab::ErrorTracking.log_exception(e, project_id: project_id, package_name: package_name)
      end
    end
  end
end
