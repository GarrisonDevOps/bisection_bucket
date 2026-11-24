# frozen_string_literal: true

module Gitlab
  module Geo
    module GeoTasks
      extend self

      def set_primary_geo_node
        node = GeoNode.new(primary: true, name: GeoNode.current_node_name, url: GeoNode.current_node_url)
        puts "Saving primary Geo node with name #{node.name} and URL #{node.url} ..."
        node.save

        if node.persisted?
          puts Rainbow("#{node.url} is now the primary Geo node").green
        else
          puts Rainbow("Error saving Geo node:\n#{node.errors.full_messages.join("\n")}").red
        end
      end

      def set_secondary_as_primary
        primary_node = GeoNode.primary_node
        current_node = GeoNode.current_node

        abort 'The primary Geo site is not set' unless primary_node
        abort 'Current node is not identified' unless current_node

        if current_node.primary?
          puts Rainbow("#{current_node.url} is already the primary Geo site").green
          # Still runs on re-runs after a partial promotion (promoted, but the
          # task failed before cron initialization), so a re-run heals it.
          initialize_cron_jobs
          # The replication mode is no longer known here, and a full partition sync is idempotent
          ::Database::PartitionManagementWorker.perform_async
          return
        end

        # The flag row replicates over LR but nothing expires the secondary's Flipper
        # cache, so a stale value here would silently skip the sequence sync.
        Feature.expire_cache(:geo_postgresql_replication_agnostic)

        logical_replication = Gitlab::Geo::LogicalReplication.in_use?

        if logical_replication
          puts 'Logical replication mode detected: syncing sequences before promotion'
          Gitlab::AppLogger.info(message: 'Promotion in logical replication mode, syncing sequences')

          Gitlab::Geo::LogicalReplication.ensure_no_active_subscription!
          first_check = check_publisher_write_activity
          Gitlab::Database::SyncSequencesWithTableData.new.execute
          # The sync can take a while on a large database, so sample again: a write that
          # started during it must be caught before the flip. Pointless after an unreachable one.
          check_publisher_write_activity if first_check&.status == :no_writes
          # A subscription re-enabled during the sync could apply rows with IDs
          # above the values we just set, so re-check before promoting.
          Gitlab::Geo::LogicalReplication.ensure_no_active_subscription!
        else
          # Streaming replication replicates sequence values; nothing to sync.
          # Printed so a skipped sync is visible in the failover terminal log.
          puts 'Streaming replication mode: skipping sequence synchronization'
          Gitlab::AppLogger.info(message: 'Promotion in streaming replication mode, skipping sequence sync')
        end

        GeoNode.transaction do
          primary_node.destroy
          current_node.update!(primary: true, enabled: true)
        end

        initialize_cron_jobs

        # As a subscriber the site only created partitions, so catch up on the detaches it skipped
        # and point the sliding-list defaults at the current partition.
        ::Database::PartitionManagementWorker.perform_async if logical_replication

        puts Rainbow("#{current_node.url} is now the primary Geo site").green
      end

      def check_publisher_write_activity
        if ENV['GEO_SKIP_WRITE_ACTIVITY_CHECK'] == '1'
          puts 'GEO_SKIP_WRITE_ACTIVITY_CHECK=1 set, skipping the publisher write activity check'
          return
        end

        result = Gitlab::Geo::PublisherWriteActivityCheck.execute
        raise Gitlab::Geo::PublisherWriteActivityCheck::Error, result.message if result.blocking?

        puts result.message
        result
      end

      # On secondary nodes, most jobs are disabled. When we promote, we aim to use the default job configuration.
      # To achieve this, we first need to enable all jobs, as many of them lack a defined `status` and cannot override
      # the `status` `disabled`. Once all jobs are enabled, we can apply the configuration and proceed with the setup.
      def initialize_cron_jobs
        Gitlab::Geo::CronManager.new.enable_all_jobs!
        Gitlab::SidekiqConfig::CronJobInitializer.execute
      end

      def update_primary_geo_node_url
        node = Gitlab::Geo.primary_node

        unless node.present?
          puts Rainbow('This is not a primary node').red
          exit 1
        end

        puts "Updating primary Geo node with URL #{node.url} ..."

        if node.update(name: GeoNode.current_node_name, url: GeoNode.current_node_url)
          puts Rainbow("#{node.url} is now the primary Geo node URL").green
        else
          puts Rainbow("Error saving Geo node:\n#{node.errors.full_messages.join("\n")}").red
          exit 1
        end
      end

      def enable_maintenance_mode
        puts 'Enabling GitLab Maintenance Mode'
        update_attrs = {
          maintenance_mode: true,
          maintenance_mode_message: ENV['MAINTENANCE_MESSAGE']
        }.compact
        ::Gitlab::CurrentSettings.update!(update_attrs)
      end

      # Note that since some non-Geo cron jobs are enabled, empty queues will be a transient state.
      # It is a sufficient check when the site is in Maintenance Mode.
      def drain_non_geo_queues
        validate_geo_queues_exist!

        puts 'Sidekiq Queues: Disabling all non-Geo cron jobs'

        disable_non_geo_cron_jobs

        puts "Sidekiq Queues: Waiting for all non-Geo queues to be empty"

        poll_selected_queues_until_empty do |queue|
          !geo_queue?(queue)
        end

        puts Rainbow("Sidekiq Queues: Non-Geo queues empty").green
      end

      def disable_non_geo_cron_jobs
        # Apply Sidekiq Cron modification to all shards
        Gitlab::SidekiqSharding::Router.with_routed_client do
          Sidekiq::Cron::Job.all.each(&:disable!) # rubocop:disable Rails/FindEach -- not an ActiveRecord::Relation

          # Do not enable `geo_sidekiq_cron_config_worker`, due to https://gitlab.com/gitlab-org/gitlab/-/issues/37135
          geo_primary_jobs.filter_map { |name| Sidekiq::Cron::Job.find(name) }.map(&:enable!)
        end
      end

      def wait_until_replicated_and_verified
        drain_geo_secondary_queues
        wait_for_database_replication
        wait_for_geo_log_cursor
        wait_for_data_replication_and_verification
      end

      # Note that since some Geo secondary cron jobs are enabled, empty Geo queues will be a transient state.
      # It is a sufficient check when the site is in Maintenance Mode, since we will be subsequently
      # checking for 100% replication and verification progress.
      #
      # Note that we need this check because e.g. Geo update events may be enqueued in Redis.
      def drain_geo_secondary_queues
        validate_geo_queues_exist!

        puts "Sidekiq Queues: Waiting for all Geo queues to be empty"

        poll_selected_queues_until_empty do |queue|
          geo_queue?(queue)
        end

        puts Rainbow("Sidekiq Queues: Geo queues empty").green
      end

      # With no user activity on the primary site, we expect no new Geo update events to arrive after waiting
      # for the current DB replication lag
      def wait_for_database_replication
        # As in set_secondary_as_primary: a stale flag would take the streaming path and skip the wait
        Feature.expire_cache(:geo_postgresql_replication_agnostic)
        return wait_for_logical_replication if Gitlab::Geo::LogicalReplication.in_use?

        lag = Gitlab::Geo::HealthCheck.new.db_replication_lag_seconds
        if lag.nil?
          puts "Database replication: Replication method unknown. Skipping wait for DB replication."
          return
        end

        puts "Database replication: Waiting for database replication to catch up"
        sleep(lag)
        puts Rainbow("Database replication: Caught up").green
      end

      # The streaming lag functions return NULL on a logical replication subscriber, so this runs the
      # subscription:drop readiness check instead. After the drop there is nothing left to check.
      def wait_for_logical_replication
        if ENV['GEO_SKIP_REPLICATION_CHECK'] == '1'
          puts "Database replication: GEO_SKIP_REPLICATION_CHECK=1 set. Skipping wait for DB replication."
          return
        end

        if Gitlab::Geo::LogicalReplication.subscription_names.empty?
          puts "Database replication: No logical replication subscription left. Skipping wait for DB replication."
          return
        end

        puts "Database replication: Waiting for the logical replication subscriber to catch up"

        result = Tasks::Gitlab::Geo::LogicalReplication.replication_readiness(ApplicationRecord.connection.raw_connection)
        abort_logical_replication_wait(result.message) if result.blocking?

        message = Rainbow("Database replication: #{result.message}")
        puts result.status == :ready ? message.green : message.yellow
      rescue PG::Error, ActiveRecord::ActiveRecordError => e
        abort_logical_replication_wait("Error checking the replication: #{e.message}")
      end

      def abort_logical_replication_wait(reason)
        abort "#{reason}\nTo promote anyway, for a disaster recovery failover, set GEO_SKIP_REPLICATION_CHECK=1."
      end

      def wait_for_geo_log_cursor
        puts "Geo log cursor: Wait Geo log cursor to have processed all events on this secondary"
        sleep(1) until geo_log_cursor_is_caught_up?
        puts Rainbow("Geo log cursor: Caught up").green
      end

      def wait_for_data_replication_and_verification
        status_check = do_status_check
        i = 0

        puts "Data replication/verification: Wait for all data to be replicated and verified"
        until status_check&.replication_verification_complete?
          status_check&.print_replication_verification_status

          sleep(1)

          # Update status
          status_check = do_status_check
          i += 1
        end
        puts Rainbow("Data replication/verification: All data successfully replicated and verified").green
      end

      def abort_if_tracking_database_not_migrated!
        return unless ::Gitlab::Geo.secondary_or_org_migration_target?
        return unless ::Gitlab::Geo::HealthCheck.new.tracking_database_needs_migration?

        abort <<~MSG
          The Geo tracking database has pending migrations, so the registry tables
          this command counts may not exist yet.

          Check which migrations are pending:

              sudo gitlab-rake db:migrate:status:geo

          then run the pending ones:

              sudo gitlab-rake db:migrate:geo

          See #{::Gitlab::Routing.url_helpers.help_page_url('administration/geo/replication/troubleshooting/common.md')}
        MSG
      end

      def do_status_check
        # Rely on Geo::MetricsUpdateWorker because:
        # 1. On large sites, it may take several minutes to produce a status
        # 2. On large sites, we do not want to run this code concurrently. GeoNodeStatus#spawn_worker will
        #    deduplicate itself if a worker is already running.
        current_node_status = GeoNodeStatus.fast_current_node_status
        return unless current_node_status

        geo_node = current_node_status.geo_node
        Gitlab::Geo::GeoNodeStatusCheck.new(current_node_status, geo_node)
      end

      def geo_log_cursor_is_caught_up?
        latest_known_id = ::Geo::EventLog.latest_event&.id
        current_cursor_id = GeoNodeStatus.new.current_cursor_last_event_id

        puts "Geo log cursor: Latest known ID: #{latest_known_id}, current cursor ID: #{current_cursor_id}"

        latest_known_id == current_cursor_id
      end

      def geo_primary_jobs
        ::Gitlab::Geo::CronManager::COMMON_GEO_JOBS +
          ::Gitlab::Geo::CronManager::COMMON_GEO_AND_NON_GEO_JOBS +
          ::Gitlab::Geo::CronManager::PRIMARY_GEO_JOBS
      end

      # Yields every queue in every Sidekiq shard. For each queue that yields
      # true, poll its size until empty.
      def poll_selected_queues_until_empty
        # Watch Sidekiq Queues on all shards
        Gitlab::SidekiqSharding::Router.with_routed_client do
          # rubocop:disable Cop/SidekiqApiUsage -- valid usage
          selected_queues = Sidekiq::Queue.all.select { |queue| yield(queue) }

          loop do
            selected_queues = selected_queues.select { |queue| queue_has_jobs?(queue) }
            break if selected_queues.empty?

            sleep(1)
          end
          # rubocop:enable Cop/SidekiqApiUsage
        end
      end

      # It's possible to configure GitLab Sidekiq queues and their names. If there are no queues
      # with Geo in the name, then raise, because this code assumes that it can easily know if Geo
      # or non-Geo jobs are drained, based on queue name.
      def validate_geo_queues_exist!
        any_geo_queues = false

        # Watch Sidekiq Queues on all shards
        Gitlab::SidekiqSharding::Router.with_routed_client do
          # rubocop:disable Cop/SidekiqApiUsage -- valid usage
          any_geo_queues ||= Sidekiq::Queue.all.any? { |queue| geo_queue?(queue) }
          # rubocop:enable Cop/SidekiqApiUsage

          break if any_geo_queues
        end

        raise "No Geo queues detected. Unable to check if Geo or non-Geo jobs are drained" unless any_geo_queues
      end

      def geo_queue?(queue)
        queue.name.include?('geo')
      end

      def queue_has_jobs?(queue)
        queue.size > 0 # rubocop:disable Style/ZeroLengthPredicate -- it's a Sidekiq::Queue object, not an Array
      end
    end
  end
end
