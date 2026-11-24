# frozen_string_literal: true

module PackageMetadata
  module Ingestion
    module CveEnrichment
      class CveEnrichmentIngestionTask
        Error = Class.new(StandardError)

        def self.execute(import_data)
          new(import_data).execute
        end

        def initialize(import_data)
          @import_data = import_data
        end

        def execute
          entries = valid_cve_enrichment_entries
          return if entries.empty?

          sql = build_upsert_sql(entries)
          ApplicationRecord.connection.execute(sql)
        end

        private

        attr_reader :import_data

        def build_upsert_sql(entries)
          # We use raw SQL instead of Rails' upsert_all because we need conditional
          # updates: only update updated_at when epss_score or is_known_exploit changes.
          # This prevents unnecessary writes and allows querying recently modified records.
          values = entries.map { |entry| quote_entry_values(entry) }.join(', ')

          <<~SQL
            INSERT INTO pm_cve_enrichment (epss_score, created_at, updated_at, cve, is_known_exploit)
            VALUES #{values}
            ON CONFLICT (cve) DO UPDATE SET
              epss_score = excluded.epss_score,
              updated_at = excluded.updated_at,
              is_known_exploit = excluded.is_known_exploit
            WHERE pm_cve_enrichment.epss_score IS DISTINCT FROM excluded.epss_score
               OR pm_cve_enrichment.is_known_exploit IS DISTINCT FROM excluded.is_known_exploit
          SQL
        end

        def quote_entry_values(entry)
          conn = ApplicationRecord.connection
          "(#{conn.quote(entry.epss_score)}, " \
            "#{conn.quote(entry.created_at)}, " \
            "#{conn.quote(entry.updated_at)}, " \
            "#{conn.quote(entry.cve)}, " \
            "#{conn.quote(entry.is_known_exploit)})"
        end

        # validates the list of provided cve_enrichment models and returns
        # only those which are valid and logs the invalid packages as an error
        def valid_cve_enrichment_entries
          cve_enrichment.map do |cve_enrichment_entry|
            if cve_enrichment_entry.invalid?
              Gitlab::ErrorTracking.track_exception(
                Error.new(
                  "invalid CVE enrichment entry"),
                cve: cve_enrichment_entry.cve,
                epss_score: cve_enrichment_entry.epss_score,
                is_known_exploit: cve_enrichment_entry.is_known_exploit,
                errors: cve_enrichment_entry.errors.to_hash
              )
              next
            end

            cve_enrichment_entry
          end.reject(&:blank?)
        end

        def cve_enrichment
          import_data.map do |data_object|
            PackageMetadata::CveEnrichment.new(
              cve: data_object.cve_id,
              epss_score: data_object.epss_score,
              is_known_exploit: data_object.is_known_exploit,
              created_at: now,
              updated_at: now
            )
          end
        end

        def now
          @now ||= Time.zone.now
        end
      end
    end
  end
end
