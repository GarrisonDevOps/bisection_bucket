# frozen_string_literal: true

namespace :gitlab do
  namespace :geo do
    namespace :logical_replication do
      namespace :publication do
        desc 'GitLab | Geo | Logical Replication | Create the publication on the Geo primary'
        task create: :gitlab_environment do
          extend Tasks::Gitlab::Geo::LogicalReplication

          abort "This is only available on the primary node" unless ::Gitlab::Geo.primary?

          db_connection.execute("CREATE PUBLICATION #{publication_name} WITH (publish_via_partition_root = true);")
        rescue ActiveRecord::StatementInvalid => si
          raise unless si.cause.is_a?(PG::DuplicateObject)

          puts "Publication already exists. Not doing anything"
        end

        desc 'GitLab | Geo | Logical Replication | Delete the publication on the Geo primary'
        task delete: :gitlab_environment do
          extend Tasks::Gitlab::Geo::LogicalReplication

          abort "This is only available on the primary node" unless ::Gitlab::Geo.primary?

          db_connection.execute("DROP PUBLICATION #{publication_name};")
        rescue ActiveRecord::StatementInvalid => si
          raise unless si.cause.is_a?(PG::UndefinedObject)

          puts "publication does not exist"
        end

        desc 'GitLab | Geo | Logical Replication | Add and remove tables on the Geo primary publication'
        task set_tables: :create do
          extend Tasks::Gitlab::Geo::LogicalReplication

          puts publication_not_via_partition_root_message unless publication_publishes_via_partition_root?

          current_tables = publication_tables(publication_name)
          roots = partition_roots

          db_connection.tables.each do |table|
            if excluded_from_publication?(table, roots)
              next unless current_tables.key?(table)

              puts "Removing #{table}"
              alter_publication("DROP", table)
            else
              next if current_tables.key?(table)

              puts "Adding #{table}"
              alter_publication("ADD", table)
            end
          end

          # Partitions that other tooling published one by one: they sit outside the search path,
          # so db_connection.tables does not list them and the loop above never reaches them.
          (current_tables.keys - db_connection.tables).each do |table|
            next unless excluded_from_publication?(table, roots)

            qualified_table = "#{current_tables[table]}.#{table}"

            puts "Removing #{qualified_table}"
            alter_publication("DROP", qualified_table)
          end
        end
      end

      namespace :preflight do
        desc 'GitLab | Geo | Logical Replication | Preflight | Check the publisher for write activity before promoting'
        task write_activity: :gitlab_environment do
          extend Tasks::Gitlab::Geo::LogicalReplication

          # Unlike the promotion path, an unset conninfo here is an error rather than a
          # degradation: the operator explicitly asked for the check to run.
          abort publisher_connection_string_message if publisher_connection_string.blank?

          result = Gitlab::Geo::PublisherWriteActivityCheck.execute(connection_string: publisher_connection_string)
          abort result.message if result.blocking?

          puts result.message
        end

        # Rails-free like the subscription tasks below, since subscription:drop runs the same check.
        desc 'GitLab | Geo | Logical Replication | Preflight | Check that the subscriber holds every published row'
        task :replication do
          require_relative './logical_replication'
          require_relative './logical_replication/readiness_check'
          extend Tasks::Gitlab::Geo::LogicalReplication

          abort subscriber_connection_string_message if subscriber_connection_string.blank?

          with_subscriber_connection do |connection|
            abort publisher_target_message if local_database_owns_publication?(connection)

            result = replication_readiness(connection)
            # Unlike the drop's retry, a detached slot is not a pass here
            abort result.message unless result.status == :ready

            puts result.message
          end
        rescue PG::Error => e
          abort "Error checking the replication: #{e.message}"
        end
      end

      # These tasks deliberately have no :gitlab_environment dependency: they run against a
      # subscriber that is not a bootable GitLab database yet, so the helper module has to be
      # required rather than autoloaded. See the operational contract in
      # ee/lib/tasks/gitlab/geo/logical_replication.rb.
      namespace :subscription do
        desc 'GitLab | Geo | Logical Replication | Subscription | Refresh the subscription on the Geo secondary'
        task :refresh do
          require_relative './logical_replication'
          extend Tasks::Gitlab::Geo::LogicalReplication

          abort subscriber_connection_string_message if subscriber_connection_string.blank?

          with_subscriber_connection do |connection|
            abort publisher_target_message if local_database_owns_publication?(connection)

            connection.exec("ALTER SUBSCRIPTION #{connection.quote_ident(subscription_name)} REFRESH PUBLICATION")

            puts "Subscription #{subscription_name} refreshed."
          end
        rescue PG::UndefinedObject
          abort subscription_missing_message
        rescue PG::Error => e
          abort "Error refreshing the subscription: #{e.message}"
        end

        desc 'GitLab | Geo | Logical Replication | Subscription | Pause the subscription on the Geo secondary'
        task :disable do
          require_relative './logical_replication'
          extend Tasks::Gitlab::Geo::LogicalReplication

          abort subscriber_connection_string_message if subscriber_connection_string.blank?

          with_subscriber_connection do |connection|
            abort publisher_target_message if local_database_owns_publication?(connection)

            subscription = current_database_subscription(connection)
            abort subscription_missing_message unless subscription

            if subscription['subenabled'] == 'f'
              puts subscription_already_disabled_message
              next
            end

            connection.exec("ALTER SUBSCRIPTION #{connection.quote_ident(subscription_name)} DISABLE")

            puts subscription_disabled_message
          end
        rescue PG::UndefinedObject
          abort subscription_missing_message
        rescue PG::Error => e
          abort "Error disabling the subscription: #{e.message}"
        end

        desc 'GitLab | Geo | Logical Replication | Subscription | Resume the subscription on the Geo secondary'
        task :enable do
          require_relative './logical_replication'
          extend Tasks::Gitlab::Geo::LogicalReplication

          abort subscriber_connection_string_message if subscriber_connection_string.blank?

          with_subscriber_connection do |connection|
            abort publisher_target_message if local_database_owns_publication?(connection)

            subscription = current_database_subscription(connection)
            abort subscription_missing_message unless subscription

            if subscription['subenabled'] == 't'
              puts subscription_already_enabled_message
              next
            end

            connection.exec("ALTER SUBSCRIPTION #{connection.quote_ident(subscription_name)} ENABLE")

            puts subscription_enabled_message
          end
        rescue PG::UndefinedObject
          abort subscription_missing_message
        rescue PG::Error => e
          abort "Error enabling the subscription: #{e.message}"
        end

        desc 'GitLab | Geo | Logical Replication | Subscription | Create the subscription on the Geo secondary'
        task :create do
          require_relative './logical_replication'
          extend Tasks::Gitlab::Geo::LogicalReplication

          abort subscriber_connection_string_message(create: true) if subscriber_connection_string.blank?
          abort publisher_connection_string_message if publisher_connection_string.blank?

          with_subscriber_connection do |connection|
            abort publisher_target_message if local_database_owns_publication?(connection)

            # copy_data = false is the documented way to re-attach to an existing publisher, so the
            # database is expected to already hold data in that case.
            if copy_data?
              begin
                abort seeded_database_message if application_settings_present?(connection)
                abort unseeded_metadata_message unless schema_migrations_present?(connection)
              rescue PG::UndefinedTable
                abort unseeded_database_message
              rescue PG::InsufficientPrivilege => e
                abort unreadable_application_settings_message(connection, e)
              end
            end

            # Scoped tightly to the CREATE so a privilege error raised by a gate query above can
            # never be reported as a missing CREATE SUBSCRIPTION privilege.
            begin
              connection.exec(<<~SQL.squish)
                CREATE SUBSCRIPTION #{connection.quote_ident(subscription_name)}
                CONNECTION #{connection.escape_literal(publisher_connection_string)}
                PUBLICATION #{connection.quote_ident(publication_name)}
                WITH (copy_data = #{copy_data?})
              SQL

              puts copy_data? ? subscription_created_message : "Subscription #{subscription_name} was created."
            rescue PG::DuplicateObject
              puts "Subscription #{subscription_name} already exists. Its connection info was NOT " \
                "verified or updated. If the publisher has changed (for example after a promotion), " \
                "check pg_subscription and recreate it with subscription:drop followed by subscription:create."
            rescue PG::InsufficientPrivilege => e
              abort create_privileges_message(connection, e)
            end
          end
        rescue PG::Error => e
          abort "Error creating the subscription: #{e.message}"
        end

        desc 'GitLab | Geo | Logical Replication | Subscription | Drop the subscription on the Geo secondary'
        task :drop do
          require_relative './logical_replication'
          require_relative './logical_replication/readiness_check'
          extend Tasks::Gitlab::Geo::LogicalReplication

          abort subscriber_connection_string_message if subscriber_connection_string.blank?

          with_subscriber_connection do |connection|
            abort publisher_target_message if local_database_owns_publication?(connection)

            subscription = current_database_subscription(connection)

            unless subscription
              puts "Subscription does not exist. Not doing anything"
              next
            end

            check_replication_readiness!(connection)

            # subslotname is nulled out by SET (slot_name = NONE), so a retry after a partial drop
            # would otherwise read nil here; Postgres defaults the slot name to the subscription name
            # and we never override it in subscription:create, so fall back to that.
            slot_name = subscription['subslotname'].presence || subscription_name

            # A drop during initial sync also strands the transient per-table slots
            # (pg_<suboid>_sync_<relid>_<sysid>) on the publisher, so clean those up too.
            sync_slot_pattern = "pg\\_#{Integer(subscription['oid'])}\\_sync\\_%"

            quoted_subscription = connection.quote_ident(subscription_name)

            # Detach the slot before DROP so it never hangs waiting on a publisher connection.
            connection.exec("ALTER SUBSCRIPTION #{quoted_subscription} DISABLE")
            connection.exec("ALTER SUBSCRIPTION #{quoted_subscription} SET (slot_name = NONE)")
            connection.exec("DROP SUBSCRIPTION #{quoted_subscription}")

            if publisher_connection_string.blank?
              puts "Set GEO_PUBLISHER_CONNECTION_STRING to drop the replication slots automatically."
              puts manual_slot_cleanup_message(slot_name, sync_slot_pattern)
            else
              begin
                drop_publisher_replication_slots(slot_name, sync_slot_pattern)
              rescue PG::Error => e
                puts "Warning: could not drop the replication slots on the publisher (#{e.message})"
                puts manual_slot_cleanup_message(slot_name, sync_slot_pattern)
              end
            end
          end
        rescue PG::Error => e
          abort "Error dropping the subscription: #{e.message}"
        end
      end

      # Rails-free for the same reason as the subscription tasks: metadata:seed runs against a
      # subscriber that holds a seeded schema and no subscription yet.
      namespace :metadata do
        desc 'GitLab | Geo | Logical Replication | Metadata | Seed schema_migrations and ' \
          'ar_internal_metadata on the Geo secondary'
        task :seed do
          require_relative './logical_replication'
          extend Tasks::Gitlab::Geo::LogicalReplication

          abort subscriber_connection_string_message if subscriber_connection_string.blank?
          abort publisher_connection_string_message if publisher_connection_string.blank?

          with_subscriber_connection do |connection|
            abort publisher_target_message if local_database_owns_publication?(connection)
            abort metadata_seed_subscription_exists_message if current_database_subscription(connection)

            missing_tables = missing_seeded_metadata_tables(connection)
            abort unseeded_metadata_tables_message(missing_tables) if missing_tables.any?

            # A live GitLab database has no publication and no subscription either, so this is the
            # check that keeps the TRUNCATE below away from one.
            begin
              abort seeded_database_message if application_settings_present?(connection)
            rescue PG::UndefinedTable
              abort unseeded_database_message
            rescue PG::InsufficientPrivilege => e
              abort unreadable_application_settings_message(connection, e)
            end

            publisher_metadata = with_publisher_connection do |publisher|
              read_publisher_metadata(publisher)
            rescue PG::InsufficientPrivilege => e
              abort unreadable_publisher_metadata_message(publisher, e)
            end

            begin
              write_subscriber_metadata(connection, **publisher_metadata)
            rescue PG::InsufficientPrivilege => e
              abort unwritable_metadata_message(connection, e)
            end

            puts metadata_seeded_message(publisher_metadata[:versions], publisher_metadata[:metadata_rows])
          end
        rescue PG::Error => e
          abort "Error seeding the replication metadata: #{e.message}"
        end

        desc 'GitLab | Geo | Logical Replication | Metadata | Verify that the Geo secondary ' \
          'schema_migrations matches the Geo primary'
        task :verify do
          require_relative './logical_replication'
          extend Tasks::Gitlab::Geo::LogicalReplication

          abort subscriber_connection_string_message if subscriber_connection_string.blank?
          abort publisher_connection_string_message if publisher_connection_string.blank?

          publisher_state = with_publisher_connection do |publisher|
            metadata_state(publisher)
          rescue PG::UndefinedTable
            abort missing_metadata_table_message('publisher')
          end

          subscriber_state, subscription = with_subscriber_connection do |connection|
            [metadata_state(connection), current_database_subscription(connection)]
          rescue PG::UndefinedTable
            abort missing_metadata_table_message('subscriber')
          end

          missing_on_subscriber = publisher_state[:versions] - subscriber_state[:versions]
          extra_on_subscriber = subscriber_state[:versions] - publisher_state[:versions]

          if missing_on_subscriber.any? || extra_on_subscriber.any?
            abort schema_migrations_mismatch_message(
              missing_on_subscriber, extra_on_subscriber,
              subscription_present: !subscription.nil?,
              subscription_enabled: subscription&.dig('subenabled') == 't'
            )
          end

          if publisher_state[:environment] != subscriber_state[:environment]
            abort environment_mismatch_message(publisher_state[:environment], subscriber_state[:environment])
          end

          puts schema_migrations_match_message(publisher_state[:versions])
        rescue PG::Error => e
          abort "Error verifying the replication metadata: #{e.message}"
        end
      end

      desc 'GitLab | Geo | Logical Replication | Sync sequences to match table data'
      task sync_sequences: :gitlab_environment do
        only_sequences = ENV['ONLY_SEQUENCES'].presence&.split(',')&.map(&:strip)

        Gitlab::Database::SyncSequencesWithTableData.new(only_sequences: only_sequences).execute
      rescue Gitlab::Database::SyncSequencesWithTableData::Error => e
        abort e.message
      end

      # Internal, hooked into db:migrate below. Migrations on an LR secondary insert into tables
      # whose rows arrived through replication, so they collide on the primary key until the local
      # sequences are advanced past the replicated ids.
      task sync_sequences_before_migrate: :gitlab_environment do
        if ENV['GEO_SKIP_SEQUENCE_SYNC'] == '1'
          puts "GEO_SKIP_SEQUENCE_SYNC=1 set, skipping the Geo logical replication sequence sync"
          next
        end

        # The gate reads geo_nodes and the feature flag, so it needs both the database and Redis. A
        # fresh install has neither: the migration being run here can be the one creating geo_nodes.
        in_use = begin
          Gitlab::Geo::LogicalReplication.in_use?
        rescue ActiveRecord::StatementInvalid, ActiveRecord::NoDatabaseError,
          ActiveRecord::ConnectionNotEstablished, PG::Error, ::Redis::BaseError => e
          warn "Could not determine whether this is a Geo logical replication secondary " \
            "(#{e.class}: #{e.message}), skipping the sequence sync"
          false
        end

        next unless in_use

        puts "Logical replication secondary detected, syncing sequences before running migrations"

        Gitlab::Database::SyncSequencesWithTableData.new.execute
      rescue Gitlab::Database::SyncSequencesWithTableData::Error => e
        abort e.message
      end
    end
  end
end

sync_sequences_hook = 'gitlab:geo:logical_replication:sync_sequences_before_migrate'

# The per-database tasks are enhanced too, because db:migrate:<name> does not go through db:migrate.
# Both are guarded: Rails defines them before any application task file is loaded, but specs load
# this file on its own.
Rake::Task['db:migrate'].enhance([sync_sequences_hook]) if Rake::Task.task_defined?('db:migrate')

ActiveRecord::Tasks::DatabaseTasks.for_each(
  ActiveRecord::Tasks::DatabaseTasks.setup_initial_database_yaml
) do |database_name|
  # The tracking database is skipped for the same reason db.rake skips it: it can be set up before
  # the main database exists, and the sequence sync reads the main database.
  next if %w[embedding geo jh].include?(database_name)

  task_name = "db:migrate:#{database_name}"

  Rake::Task[task_name].enhance([sync_sequences_hook]) if Rake::Task.task_defined?(task_name)
end
