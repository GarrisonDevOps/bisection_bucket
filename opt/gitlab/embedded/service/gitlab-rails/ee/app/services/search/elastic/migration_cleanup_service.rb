# frozen_string_literal: true

module Search
  module Elastic
    class MigrationCleanupService
      include Gitlab::Loggable

      BATCH_SIZE = 100
      SCROLL_TIMEOUT = '1m'
      MIGRATION_REMOVAL_PERIOD = 2.months

      def self.execute(...)
        new(...).execute
      end

      def initialize(dry_run: true, logger: nil)
        @dry_run = dry_run
        @logger = logger || ::Gitlab::Elasticsearch::Logger.build
      end

      def execute
        return false unless ::Gitlab::Saas.feature_available?(:advanced_search)
        return false unless ::Gitlab::CurrentSettings.elasticsearch_indexing?

        @migrations_to_remove = []
        @total_removed = 0

        response = initial_search
        scroll_id = response['_scroll_id']

        while response
          process_batch(response['hits']['hits'])
          response = scroll_search(scroll_id)
          scroll_id = response['_scroll_id'] if response
        end

        remove_migrations_from_index(@migrations_to_remove)

        cleanup_scroll(scroll_id)

        @total_removed
      end

      private

      attr_accessor :migrations_to_remove, :dry_run, :logger

      def helper
        @helper ||= ::Search::Elastic::Helper.default
      end

      def client
        @client ||= ::Gitlab::Search::Client.new
      end

      def initial_search
        client.search(
          index: helper.migrations_index_name,
          scroll: SCROLL_TIMEOUT,
          body: {
            query: { match_all: {} },
            size: BATCH_SIZE
          }
        )
      end

      def scroll_search(scroll_id)
        response = client.scroll(
          body: { scroll_id: scroll_id },
          scroll: SCROLL_TIMEOUT
        )
        response['hits']['hits'].any? ? response : nil
      end

      def process_batch(hits)
        hits.each do |document|
          migration_id = document['_id']
          migration = ::Elastic::DataMigrationService[migration_id.to_i]
          next if migration

          started_at = document.dig('_source', 'started_at')
          next unless started_at.present? && started_at > MIGRATION_REMOVAL_PERIOD.ago

          migration_name = document.dig('_source', 'name')
          logger.warn(build_structured_payload(message: 'Migration not found',
            dry_run: dry_run, migration_id: migration_id, migration_name: migration_name))

          @migrations_to_remove << migration_id
        end
      end

      def cleanup_scroll(scroll_id)
        client.clear_scroll(
          body: { scroll_id: scroll_id }
        )
      end

      def remove_migrations_from_index(migrations_to_remove)
        migrations_to_remove.each do |migration_id|
          next if dry_run

          client.delete(index: helper.migrations_index_name, id: migration_id)
          logger.info(build_structured_payload(message: 'Migration removed from index', migration_id: migration_id))
          @total_removed += 1
        end
      end
    end
  end
end
