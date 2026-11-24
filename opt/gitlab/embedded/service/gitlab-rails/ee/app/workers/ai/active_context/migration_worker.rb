# frozen_string_literal: true

module Ai
  module ActiveContext
    class MigrationWorker
      include ::ApplicationWorker
      include ::CronjobQueue
      include Gitlab::ExclusiveLeaseHelpers
      prepend ::Geo::SkipSecondary

      LOCK_TIMEOUT = 30.minutes
      LOCK_SLEEP_SEC = 2
      LOCK_RETRIES = 10

      idempotent!
      pause_control :active_context
      worker_resource_boundary :cpu
      urgency :low
      data_consistency :sticky
      feature_category :semantic_code_search
      defer_on_database_health_signal :gitlab_main, [:ai_active_context_migrations], 10.minutes

      def perform
        return false unless preflight_checks

        if failed_migrations?
          log 'Found failed migrations. All future migrations will be halted. Exiting'
          return
        end

        preprocess_migration_records!

        in_lock(self.class.name.underscore, ttl: LOCK_TIMEOUT, retries: LOCK_RETRIES, sleep_sec: LOCK_SLEEP_SEC) do
          execute_current_migration
        end
      end

      private

      def preflight_checks
        unless ::ActiveContext.indexing?
          log 'Indexing is disabled or adapter is not configured. Execution is skipped.'
          return false
        end

        true
      end

      def failed_migrations?
        migrations.failed.any?
      end

      def preprocess_migration_records!
        migration_files = migration_dictionary_instance.migrations(versions_only: true)
        migration_records = migrations.pluck(:version) # rubocop:disable CodeReuse/ActiveRecord -- scoped to connection's AR association

        create_missing_migration_records!(migration_files - migration_records)
        delete_orphaned_migration_records!(migration_records - migration_files)
        reevaluate_skipped_migrations!
      end

      def execute_current_migration
        migration_record = migrations.current

        unless migration_record
          log 'No pending migrations to process'
          return true
        end

        migration_class = find_migration_class(migration_record.version)
        migration_instance = migration_class.new

        if migration_instance.skip?
          mark_migration_as_skipped(migration_record)
          return true
        end

        process_migration!(migration_record, migration_instance)

        true
      end

      def mark_migration_as_skipped(migration_record)
        return if migration_record.skipped?

        log "Skipping migration #{migration_record.version}"
        migration_record.skipped!
      end

      def process_migration!(migration_record, migration_instance)
        log "Starting migration #{migration_record.version}"

        migration_record.mark_as_started! unless migration_record.in_progress?
        migration_instance.migrate!

        log "Marking migration #{migration_record.version} as completed"
        migration_record.mark_as_completed!
      rescue StandardError => e
        migration_record.decrease_retries!(e)

        log "Migration #{migration_record.version} failed: #{e.message}. Retries left: #{migration_record.retries_left}"
      end

      def create_missing_migration_records!(versions)
        return unless versions.any?

        connection = adapter.connection

        versions.each do |version|
          ::Ai::ActiveContext::Migration.create!(connection: connection, version: version)
        end

        log "Created missing migration records for #{versions.join(', ')}"
      end

      def delete_orphaned_migration_records!(versions)
        return unless versions.any?

        migrations.where(version: versions).delete_all # rubocop:disable CodeReuse/ActiveRecord -- scoped to connection's AR association

        log "Deleted orphaned migration records for #{versions.join(', ')}"
      end

      def reevaluate_skipped_migrations!
        migrations.skipped.each do |migration_record|
          migration_class = find_migration_class(migration_record.version)
          migration_instance = migration_class.new

          unless migration_instance.skip?
            log "Migration #{migration_record.version} no longer skipped, marking as pending"
            migration_record.pending!
          end
        end
      end

      def migrations
        adapter.connection.migrations
      end

      def find_migration_class(version)
        migration_dictionary_instance.find_by_version(version)
      end

      def migration_dictionary_instance
        @migration_dictionary_instance ||= ::ActiveContext::Migration::Dictionary.instance
      end

      def log(message)
        ::ActiveContext::Config.logger.info(structured_payload(message: "#{self.class}: #{message}"))
      end

      def adapter
        @adapter ||= ::ActiveContext.adapter
      end
    end
  end
end
