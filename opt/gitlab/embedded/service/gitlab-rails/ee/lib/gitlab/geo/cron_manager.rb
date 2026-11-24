# frozen_string_literal: true

module Gitlab
  module Geo
    class CronManager
      # This class helps to react to state changes in node types. We currently have non-geo nodes, primary and
      # secondary geo nodes. This manager gets for example executed during Rails initialization, a promotion from a
      # secondary to a primary node, during and also every minute by the `Geo::SidekiqCronConfigWorker` to ensure
      # the correct status of the geo jobs.

      include ::Gitlab::Utils::StrongMemoize

      COMMON_GEO_JOBS = %w[
        geo_metrics_update_worker
        geo_verification_cron_worker
      ].freeze

      # These jobs run on everything, whether Geo is enabled or not
      COMMON_GEO_AND_NON_GEO_JOBS = %w[
        repository_check_worker
        concurrency_limit_resume_worker
      ].freeze

      PRIMARY_GEO_JOBS = %w[
        geo_ci_job_artifact_verification_summary_calculator_worker
        geo_prune_event_log_worker
      ].freeze

      SECONDARY_GEO_JOBS = %w[
        geo_checksum_mismatch_reporting_worker
        geo_registry_blob_location_backfill_cron_worker
        geo_registry_sync_worker
        geo_repository_registry_sync_worker
        geo_secondary_registry_consistency_worker
        geo_secondary_usage_data_cron_worker
        geo_sync_timeout_cron_worker
      ].freeze

      # DDL is not replicated, so a logical replication secondary creates its own partitions. It never drops
      # them, so the dropper stays disabled.
      LOGICAL_REPLICATION_SECONDARY_JOBS = %w[
        postgres_dynamic_partitions_manager
      ].freeze

      CONFIG_WATCHER = 'geo_sidekiq_cron_config_worker'
      CONFIG_WATCHER_CLASS = 'Geo::SidekiqCronConfigWorker'

      GEO_JOBS = (COMMON_GEO_JOBS + PRIMARY_GEO_JOBS + SECONDARY_GEO_JOBS).freeze
      GEO_ALWAYS_ENABLED_JOBS = (COMMON_GEO_JOBS + COMMON_GEO_AND_NON_GEO_JOBS).freeze

      def execute
        return unless Geo.connected?

        if current_node&.primary?
          configure_primary
        elsif current_node&.secondary?
          configure_secondary
        elsif current_node&.org_migration_target?
          configure_org_migration_target
        else
          configure_non_geo_site
        end
      end

      def create_watcher!
        job(CONFIG_WATCHER)&.destroy

        Sidekiq::Client.via(sidekiq_redis_pool) do
          Sidekiq::Cron::Job.create(
            name: CONFIG_WATCHER,
            cron: '*/1 * * * *',
            class: CONFIG_WATCHER_CLASS
          )
        end
      end

      # This method ensures disabled secondary geo jobs are enabled when promoting to a primary node.
      # Applying the default config without `status` attributes won't enable previously disabled jobs.
      def enable_all_jobs!
        enable_jobs!(all_jobs)
      end

      private

      # We avoid the memoized `Gitlab::Geo.current_node`, in particular because it can be
      # stale during `rake set_secondary_as_primary`.
      def current_node
        GeoNode.current_node
      end
      strong_memoize_attr :current_node

      def configure_primary
        disable!(SECONDARY_GEO_JOBS)

        enable!(GEO_ALWAYS_ENABLED_JOBS + PRIMARY_GEO_JOBS)
      end

      def configure_secondary
        names = GEO_ALWAYS_ENABLED_JOBS + SECONDARY_GEO_JOBS
        if Gitlab::Geo::LogicalReplication.subscriber?(ApplicationRecord.connection)
          names += LOGICAL_REPLICATION_SECONDARY_JOBS
        end

        disable_all_except!(names)
        enable!(names)
      end

      def configure_non_geo_site
        disable!(GEO_JOBS)

        enable!(COMMON_GEO_AND_NON_GEO_JOBS)
      end

      def configure_org_migration_target
        disable!(PRIMARY_GEO_JOBS)

        enable!(GEO_ALWAYS_ENABLED_JOBS + SECONDARY_GEO_JOBS)
      end

      def enable!(names)
        enable_jobs!(jobs(names))
      end

      def disable!(names)
        disable_jobs!(jobs(names))
      end

      def enable_all_except!(names)
        enable_jobs!(all_jobs_except(names))
      end

      def disable_all_except!(names)
        disable_jobs!(all_jobs_except(names))
      end

      def enable_jobs!(jobs)
        Sidekiq::Client.via(sidekiq_redis_pool) do
          jobs.each { |job| job.enable! unless job.enabled? }
        end
      end

      def disable_jobs!(jobs)
        Sidekiq::Client.via(sidekiq_redis_pool) do
          jobs.each { |job| job.disable! unless job.disabled? }
        end
      end

      def all_jobs_except(names = [])
        all_jobs.reject { |job| names.include?(job.name) }
      end

      def all_jobs
        Sidekiq::Client.via(sidekiq_redis_pool) { Sidekiq::Cron::Job.all }
      end

      def jobs(names)
        names.filter_map { |name| job(name) }
      end

      def job(name)
        Sidekiq::Client.via(sidekiq_redis_pool) do
          Sidekiq::Cron::Job.find(name)
        end
      end

      # Sidekiq::Cron::Job config isn't tied to a specific worker's `store` option, so it
      # always lives on the main shard, same as everything does before sharding is enabled.
      def sidekiq_redis_pool
        _, pool = Gitlab::SidekiqSharding::Router.get_shard_instance( # rubocop:disable Cop/RedisQueueUsage -- assigning a constant is acceptable
          Gitlab::Redis::Queues::SIDEKIQ_MAIN_SHARD_INSTANCE_NAME
        )
        pool
      end
      strong_memoize_attr :sidekiq_redis_pool
    end
  end
end
