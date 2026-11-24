# frozen_string_literal: true

module Elastic
  class DataMigrationService
    MIGRATIONS_PATH = 'ee/elastic/migrate'
    MIGRATION_REGEXP = /\A([0-9]+)_([_a-z0-9]*)\.rb\z/
    CACHE_TIMEOUT = 30.minutes

    ClusterUnreachableError = Class.new(StandardError)

    class << self
      def migration_files
        Dir[migrations_full_path]
      end

      def migrations(exclude_skipped: false)
        migrations = migration_files.map do |file|
          version, name = parse_migration_filename(file)

          Elastic::MigrationRecord.new(version: version.to_i, name: name.camelize, filename: file)
        end

        migrations.reject!(&:skip?) if exclude_skipped
        migrations.sort_by(&:version)
      end

      def [](version)
        migrations.find { |m| m.version == version }
      end

      def find_by_name(name)
        migrations.find { |migration| migration.name_for_key == name.to_s.underscore }
      end

      def find_by_name!(name)
        migration = find_by_name(name)

        raise ArgumentError, "Couldn't find Elastic::Migration with name='#{name}'" unless migration
        raise ArgumentError, "Elastic::Migration with name='#{name}' is marked as obsolete" if migration.obsolete?

        migration
      end

      def drop_migration_has_finished_cache!(migration)
        Rails.cache.delete cache_key(:migration_has_finished, migration.name_for_key)
      end

      def migration_has_finished?(name)
        Rails.cache.fetch cache_key(:migration_has_finished, name.to_s.underscore), expires_in: CACHE_TIMEOUT do
          migration_has_finished_uncached?(name)
        end
      end

      def migration_has_finished_uncached?(name)
        migration = find_by_name(name)

        !!migration&.load_from_index&.dig('_source', 'completed')
      end

      def migration_halted?(migration)
        Rails.cache.fetch cache_key(:migration_halted, migration.name_for_key), expires_in: CACHE_TIMEOUT do
          migration_halted_uncached?(migration)
        end
      end

      def drop_migration_halted_cache!(migration)
        Rails.cache.delete cache_key(:migration_halted, migration.name_for_key)
      end

      def migration_halted_uncached?(migration)
        !!migration&.load_from_index&.dig('_source', 'state', 'halted')
      end

      def pending_migrations?
        return false unless ::Gitlab::CurrentSettings.elasticsearch_indexing?

        migrations(exclude_skipped: true).reverse.any? do |migration|
          !migration_has_finished_uncached?(migration.name_for_key)
        end
      end

      def pending_migrations
        unless ::Gitlab::CurrentSettings.elasticsearch_indexing?
          logger.info(class: name, message: 'skip checking pending_migrations elasticsearch_indexing is disabled.')

          return []
        end

        migrations(exclude_skipped: true).select do |migration|
          !migration_has_finished_uncached?(migration.name_for_key)
        end
      end

      # Raising variant of .pending_migrations?. The non-raising predicate cannot
      # distinguish "no migrations are pending" from "the cluster could not be
      # read", because Elastic::MigrationRecord#load_from_index swallows every
      # error and returns nil.
      def pending_migrations!
        return false unless ::Gitlab::CurrentSettings.elasticsearch_indexing?

        verify_cluster_reachable!

        pending_migrations?
      end

      def index_created_by_pending_migration?(klass)
        pending_create_index_target_classes.include?(klass)
      end

      def pending_create_index_target_classes
        pending_migrations.each_with_object(Set.new) do |migration, set|
          next unless migration.try(:creates_standalone_index?)

          target = migration.try(:target_class)
          set << target if target
        end
      end

      def halted_migrations?
        migrations(exclude_skipped: true).reverse.any? do |migration|
          migration_halted?(migration)
        end
      end

      def halted_migration
        migrations(exclude_skipped: true).reverse.find do |migration|
          migration_halted?(migration)
        end
      end

      def mark_all_as_completed!
        bulk_request = migrations.flat_map do |migration|
          drop_migration_has_finished_cache!(migration)
          drop_migration_halted_cache!(migration)

          [
            { index: { _id: migration.version } },
            migration.to_h(completed: true, halted: false)
          ]
        end

        Gitlab::Search::Client.new.bulk(index: helper.migrations_index_name, body: bulk_request, refresh: true)
      end

      private

      # A ping can succeed even when the index read fails (auth error, timeout,
      # or a 5xx status). This method checks both.
      #
      # Transport::Error is also rescued. It is the parent class for HTTP
      # statuses and pool errors that Gitlab::Search::Client does not convert.
      def verify_cluster_reachable!
        raise ClusterUnreachableError, 'Search cluster ping failed.' unless helper.ping?

        helper.index_exists?(index_name: helper.migrations_index_name)
      rescue ::Gitlab::Search::Client::ConnectionError,
        ::Gitlab::Search::Client::AuthorizationError,
        ::Elastic::TimeoutError,
        ::Elasticsearch::Transport::Transport::Error => e
        raise ClusterUnreachableError, "Unable to read the search migrations index: #{transport_error_detail(e)}"
      end

      # ConnectionError and AuthorizationError override #message with a fixed
      # sentence. The real detail stays on #errors. Other rescued classes keep
      # the detail on #message.
      def transport_error_detail(error)
        detail = error.errors if error.respond_to?(:errors)

        detail.presence || error.message
      end

      def cache_key(method_name, *additional_key)
        [name, method_name, *additional_key]
      end

      def parse_migration_filename(filename)
        File.basename(filename).scan(MIGRATION_REGEXP).first
      end

      def migrations_full_path
        Rails.root.join(MIGRATIONS_PATH, '**', '[0-9]*_*.rb').to_s
      end

      def helper
        @helper ||= ::Search::Elastic::Helper.default
      end

      def logger
        @logger ||= ::Gitlab::Elasticsearch::Logger.build
      end
    end
  end
end
