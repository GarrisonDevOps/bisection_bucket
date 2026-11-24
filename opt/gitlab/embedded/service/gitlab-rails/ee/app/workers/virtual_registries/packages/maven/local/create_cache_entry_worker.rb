# frozen_string_literal: true

module VirtualRegistries
  module Packages
    module Maven
      module Local
        class CreateCacheEntryWorker
          include ApplicationWorker

          data_consistency :sticky

          queue_namespace :dependency_proxy_blob
          feature_category :virtual_registry
          urgency :low

          defer_on_database_health_signal :gitlab_main,
            [:virtual_registries_packages_maven_cache_local_entries],
            5.minutes
          deduplicate :until_executed
          idempotent!

          def perform(upstream_id, package_file_id, relative_path)
            return unless ::Packages::PackageFile.id_in(package_file_id).exists?

            upstream = ::VirtualRegistries::Packages::Maven::Local::Upstream.find_by_id(upstream_id)

            return unless upstream

            attrs = {
              group_id: upstream.group_id,
              upstream_id: upstream_id,
              relative_path: relative_path,
              package_file_id: package_file_id,
              upstream_checked_at: Time.current
            }

            entry = ::VirtualRegistries::Packages::Maven::Cache::Local::Entry.new(attrs)

            # Use :upsert validation context so that the uniqueness
            # validation on [upstream_id, group_id, relative_path] is skipped.
            entry.validate!(:upsert)

            ::VirtualRegistries::Packages::Maven::Cache::Local::Entry.upsert(
              attrs,
              unique_by: %i[upstream_id group_id relative_path]
            )
          rescue ActiveRecord::ActiveRecordError => e
            Gitlab::ErrorTracking.log_exception(e, upstream_id:, package_file_id:, relative_path:)
          end
        end
      end
    end
  end
end
