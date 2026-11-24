# frozen_string_literal: true

module ActiveRecord
  module Tasks
    module DatabaseTasks
      def migrate_status
        # rubocop:disable Database/MultipleDatabases -- From Rails base code which doesn't follow our style guide
        # rubocop:disable Rails/Output -- From Rails base code which doesn't follow our style guide
        Kernel.abort "Schema migrations table does not exist yet." unless connection_pool.schema_migration.table_exists?

        puts "\ndatabase: #{ActiveRecord::Base.connection_db_config.database}\n\n"
        puts "#{'Status'.center(8)}  #{'Migration ID'.ljust(14)}  #{'Type'.ljust(7)}  #{'Milestone'.ljust(11)}  Name"
        puts "-" * 50
        status_with_milestones.each do |status, version, type, milestone, name|
          puts "#{status.center(8)}  #{version.ljust(14)}  #{type.ljust(7)}  #{milestone.ljust(11)}  #{name}"
        end
        puts
        # rubocop:enable Rails/Output
      end

      def status_with_milestones
        all_versions = connection_pool.schema_migration.versions.map(&:to_i)

        # `version` is actually an object that has its own internal rules for sorting.
        # The following line is vital to displaying migration status in correct execution order.
        migrations = connection_pool.migration_context.migrations.sort_by(&:version)

        migrations_without_files = (all_versions - migrations.map { |m| m.version.to_i })
        all_migrations = migrations.map do |m|
          [
            (all_versions.include?(m.version.to_i) ? 'up' : 'down'),
            m.version.to_s,
            m.version.try(:type).to_s,
            m.try(:milestone).to_s,
            m.name
          ]
        end
        migrations_without_files.each do |version|
          all_migrations << [
            'up',
            version.to_s,
            '',
            '',
            '********** NO FILE **********'
          ]
        end

        all_migrations
      end

      def connection_pool
        ActiveRecord::Base.connection_pool
      end
      # rubocop:enable Database/MultipleDatabases
    end
  end
end

ActiveSupport.on_load(:active_record) do
  Gitlab::Patch::AdditionalDatabaseTasks.patch!
end
