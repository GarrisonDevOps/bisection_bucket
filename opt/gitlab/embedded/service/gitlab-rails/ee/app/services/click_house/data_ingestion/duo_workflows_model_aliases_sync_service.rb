# frozen_string_literal: true

module ClickHouse # rubocop:disable Gitlab/BoundedContexts -- matches the existing ClickHouse:: namespace used by every sibling
  module DataIngestion
    # Re-resolves every raw `model_used` spelling on each run, so catalog changes
    # reach existing rows without a backfill. Unresolved spellings are never written.
    # See https://gitlab.com/gitlab-org/gitlab/-/work_items/631302
    class DuoWorkflowsModelAliasesSyncService
      include Gitlab::ExclusiveLeaseHelpers

      MAX_TTL = 5.minutes.to_i

      # A rescan, not a cursor: an unresolved spelling is never stored, so only a rescan
      # picks it up once the catalog learns it. LowCardinality keeps the scan cheap.
      SPELLINGS_QUERY = <<~SQL.squish
        SELECT DISTINCT model_used FROM duo_workflow_session_enrichments WHERE model_used != ''
      SQL

      # A deleted spelling reads as absent, so a later run writes it again if it still resolves.
      CURRENT_ALIASES_QUERY = <<~SQL.squish
        SELECT
          model_used,
          argMax(model_key, version) AS model_key,
          argMax(hosting, version) AS hosting
        FROM duo_workflows_model_aliases
        GROUP BY model_used
        HAVING argMax(deleted, version) = false
      SQL

      CSV_MAPPING = {
        model_used: ->(row) { row[:model_used] },
        model_key: ->(row) { row[:model_key] },
        hosting: ->(row) { row[:hosting] }
      }.freeze

      INSERT_QUERY = <<~SQL.squish
        INSERT INTO duo_workflows_model_aliases (#{CSV_MAPPING.keys.join(',')})
        FORMAT CSV
      SQL

      def self.enabled?
        ::Gitlab::ClickHouse.configured?
      end

      def execute
        unless self.class.enabled?
          return ServiceResponse.error(message: 'Disabled: ClickHouse database is not configured.',
            reason: :db_not_configured)
        end

        in_lock(self.class.name.underscore, ttl: MAX_TTL, retries: 0) do
          ServiceResponse.success(payload: sync_aliases)
        end
      rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError => e
        ServiceResponse.error(message: e.message, reason: :skipped)
      end

      private

      def sync_aliases
        current = current_aliases
        spellings = ClickHouse::Client.select(SPELLINGS_QUERY, :main).flat_map(&:values) | current.keys
        # Without spellings the catalog is never consulted, so the payload must not fetch it either.
        return { spellings: 0, records_written: 0 } if spellings.empty?

        metadata = ::Ai::DuoWorkflows::ModelMetadata.new(spellings)

        rows = metadata.to_h.filter_map do |model_used, entry|
          next unless entry.model_key

          row = { model_used: model_used, model_key: entry.model_key, hosting: entry.hosting.to_s }
          row unless current[model_used] == row.slice(:model_key, :hosting)
        end

        insert(rows)

        { spellings: spellings.size, records_written: rows.size, catalog_available: metadata.catalog_available? }
      end

      def current_aliases
        ClickHouse::Client.select(CURRENT_ALIASES_QUERY, :main).to_h do |row|
          [row['model_used'], { model_key: row['model_key'], hosting: row['hosting'] }]
        end
      end

      def insert(rows)
        return if rows.empty?

        CsvBuilder::Gzip.new(rows, CSV_MAPPING).render do |tempfile|
          File.open(tempfile.path) { |f| ClickHouse::Client.insert_csv(INSERT_QUERY, f, :main) }
        end
      end
    end
  end
end
