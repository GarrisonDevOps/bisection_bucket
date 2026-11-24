# frozen_string_literal: true

module Gitlab
  module Database
    module Partitioning
      PARTITION_EXCLUDED_DATABASES = %w[embedding jh geo].freeze

      class TableWithoutModel < Gitlab::Database::SharedModel
        include PartitionedTable
      end

      class << self
        def register_models(models)
          models.each do |model|
            raise "#{model} should have partitioning strategy defined" unless model.respond_to?(:partitioning_strategy)

            registered_models << model
          end
        end

        def clear_registered_models
          @registered_models = Set.new
        end

        def register_tables(tables)
          registered_tables.merge(tables)
        end

        def clear_registered_tables
          @registered_tables = Set.new
        end

        def sync_partitions_ignore_db_error(analyze: false)
          sync_partitions(analyze: analyze) unless ENV['DISABLE_POSTGRES_PARTITION_CREATION_ON_STARTUP']
        rescue ActiveRecord::ActiveRecordError, PG::Error, ::Redis::BaseError, ::RedisClient::Error
          # ignore - happens when Rake tasks yet have to create a database or Redis is not up, e.g. for testing
        end

        # Returns [blocking_flags, synced]: the feature flags that blocked the
        # sync, and whether every requested database was synced
        def sync_partitions(
          models_to_sync = registered_for_sync,
          only_on: nil,
          analyze: true,
          analyze_tables_with_default_interval: false,
          owner_db_only: Rails.env.production?
        )
          blocking_flag = blocking_feature_flag(only_on)

          if blocking_flag
            Gitlab::AppLogger.warn(
              message: 'Skipping sync of dynamic postgres partitions', feature_flag: blocking_flag
            )
            return [[blocking_flag], false]
          end

          Gitlab::AppLogger.info(message: 'Syncing dynamic postgres partitions')

          skipped_flags = database_names(only_on).filter_map do |database_name|
            sync_database(
              database_name, models_to_sync,
              analyze: analyze, analyze_tables_with_default_interval: analyze_tables_with_default_interval
            )
          end

          unless owner_db_only || only_on
            models_to_sync.each do |model|
              # Skip because Gitlab::Database::EachDatabase already synced this to all dbs
              next if model < ::Gitlab::Database::SharedModel && !(model < TableWithoutModel)

              model_connection_name = model.connection_db_config.name
              Gitlab::Database::EachDatabase.each_connection(include_shared: false) do |connection, connection_name|
                next if connection_name == model_connection_name
                next if blocking_feature_flag(connection_name)

                PartitionManager.new(model, connection: connection).sync_partitions(
                  analyze: analyze,
                  analyze_tables_with_default_interval: analyze_tables_with_default_interval
                )
              end
            end
          end

          Gitlab::AppLogger.info(message: 'Finished sync of dynamic postgres partitions')

          [skipped_flags, skipped_flags.empty?]
        end

        def report_metrics(models_to_monitor = registered_models)
          partition_monitoring = PartitionMonitoring.new

          Gitlab::Database::EachDatabase.each_model_connection(models_to_monitor) do |model|
            partition_monitoring.report_metrics_for_model(model)
          end
        end

        def drop_detached_partitions
          blocking_flag = blocking_feature_flag

          if blocking_flag
            Gitlab::AppLogger.warn(
              message: 'Skipping drop of detached postgres partitions', feature_flag: blocking_flag
            )
            return blocking_flag
          end

          Gitlab::AppLogger.info(message: 'Dropping detached postgres partitions')

          Gitlab::Database::EachDatabase.each_connection do |_connection, database_name|
            unless_ff_gated(database_name, 'Skipping drop of detached postgres partitions') do
              DetachedPartitionDropper.new.perform
            end
          end

          Gitlab::AppLogger.info(message: 'Finished dropping detached postgres partitions')
        end

        def finalize_pending_detach_partitions
          blocking_flag = blocking_feature_flag

          if blocking_flag
            Gitlab::AppLogger.warn(
              message: 'Skipping finalizing pending detach postgres partitions', feature_flag: blocking_flag
            )
            return blocking_flag
          end

          Gitlab::Database::EachDatabase.each_connection do |_connection, database_name|
            unless_ff_gated(database_name, 'Skipping finalizing pending detach postgres partitions') do
              PendingDetachPartitionFinalizer.new.perform
            end
          end
        end

        def registered_models
          @registered_models ||= Set.new
        end

        def registered_tables
          @registered_tables ||= Set.new
        end

        def registered_for_sync
          registered_models + registered_tables.map do |table|
            table_without_model(**table)
          end
        end

        private

        def sync_database(database_name, models, analyze:, analyze_tables_with_default_interval:)
          unless_ff_gated(database_name, 'Skipping sync of dynamic postgres partitions') do
            lease = DatabaseSyncLease.new(database_name)
            synced = lease.try_obtain_lease { sync_models_under_lease(database_name, models, lease) }
            next unless analyze && synced

            synced.each do |manager, created_partitions|
              manager.analyze_partitions(
                created_partitions, analyze_tables_with_default_interval: analyze_tables_with_default_interval
              )
            end
          end
        end

        def sync_models_under_lease(database_name, models, lease)
          synced = []

          Gitlab::Database::EachDatabase.each_model_connection(models, only_on: database_name) do |model|
            manager = PartitionManager.new(model)
            created_partitions = manager.create_and_detach_partitions
            synced << [manager, created_partitions] if created_partitions
            break unless lease.renew
          end

          synced
        end

        def database_names(only_on)
          selected_names = Array.wrap(only_on).map(&:to_s)

          Gitlab::Database.database_base_models_with_gitlab_shared.keys.select do |name|
            selected_names.empty? || selected_names.include?(name)
          end
        end

        def table_without_model(
          table_name:, partitioned_column:, strategy:, limit_connection_names: nil,
          **strategy_args)
          Class.new(TableWithoutModel).tap do |klass|
            klass.table_name = table_name
            klass.partitioned_by(partitioned_column, strategy: strategy, **strategy_args)
            klass.limit_connection_names = limit_connection_names
          end
        end

        def blocking_feature_flag(database_name = nil)
          if Feature.enabled?(:disallow_database_ddl_feature_flags, type: :ops)
            :disallow_database_ddl_feature_flags
          elsif Feature.disabled?(:partition_manager_sync_partitions, type: :ops)
            :partition_manager_sync_partitions
          else
            database_blocking_feature_flag(database_name)
          end
        end

        def unless_ff_gated(database_name, message)
          blocking_flag = database_blocking_feature_flag(database_name)

          if blocking_flag
            Gitlab::AppLogger.warn(message: message, feature_flag: blocking_flag, database_name: database_name)
            return blocking_flag
          end

          yield

          nil
        end

        def database_blocking_feature_flag(database_name)
          return unless database_name

          disabled =
            case database_name.to_s
            when 'main' then Feature.disabled?(:partition_manager_sync_partitions_main, type: :ops)
            when 'ci' then Feature.disabled?(:partition_manager_sync_partitions_ci, type: :ops)
            when 'sec' then Feature.disabled?(:partition_manager_sync_partitions_sec, type: :ops)
            end

          :"partition_manager_sync_partitions_#{database_name}" if disabled
        end
      end
    end
  end
end
