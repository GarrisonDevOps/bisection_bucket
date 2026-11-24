# frozen_string_literal: true

module VirtualRegistries
  module Cache
    class MarkEntriesForDestructionWorker
      include ApplicationWorker

      BATCH_SIZE = 500
      GLOBAL_ID_LOCATE_OPTIONS = {
        only: [
          ::VirtualRegistries::Packages::Maven::Upstream,
          ::VirtualRegistries::Packages::Npm::Upstream,
          ::VirtualRegistries::Container::Upstream
        ]
      }.freeze

      data_consistency :sticky
      queue_namespace :dependency_proxy_blob
      feature_category :virtual_registry
      urgency :low
      defer_on_database_health_signal :gitlab_main,
        %i[virtual_registries_packages_maven_cache_remote_entries virtual_registries_container_cache_remote_entries],
        5.minutes
      deduplicate :until_executed
      idempotent!

      def perform(upstream_gid)
        upstream = safe_locate(upstream_gid)

        return unless upstream

        upstream.default_cache_entries.each_batch(of: BATCH_SIZE, column: :iid) do |batch|
          batch.update_all(
            status: :pending_destruction,
            updated_at: Time.current
          )
        end
      end

      private

      def safe_locate(gid)
        Gitlab::GlobalId.safe_locate(
          gid,
          on_error: ->(e) { Gitlab::ErrorTracking.track_exception(e, gid: gid, worker: self.class.name) },
          options: GLOBAL_ID_LOCATE_OPTIONS
        )
      end
    end
  end
end
