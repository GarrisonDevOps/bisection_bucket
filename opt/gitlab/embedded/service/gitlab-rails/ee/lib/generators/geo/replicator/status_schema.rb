# frozen_string_literal: true

module Geo
  module Replicator
    # Builds the Geo status fields, API-doc JSON values, and Prometheus metric rows for a
    # replicable. Pure logic (no Thor/filesystem state), unit-testable in isolation.
    class StatusSchema
      def initialize(file_name:, replicable_title_plural:, milestone:)
        @status_field_prefix = "#{file_name}s"
        @replicable_title_plural = replicable_title_plural
        @milestone = milestone
      end

      attr_reader :status_field_prefix

      # Ordered field => JSON-schema type for the Geo status fixtures.
      def status_property_definitions
        defs = {}
        %w[count checksum_total_count checksummed_count checksum_failed_count synced_count failed_count
          registry_count verification_total_count verified_count verification_failed_count].each do |suffix|
          defs["#{status_field_prefix}_#{suffix}"] = { 'type' => %w[integer null] }
        end
        %w[synced_in_percentage verified_in_percentage].each do |suffix|
          defs["#{status_field_prefix}_#{suffix}"] = { 'type' => 'string' }
        end
        defs["#{status_field_prefix}_oldest_unsynced_time"] = { 'type' => 'integer' }
        defs
      end

      def status_fields
        status_property_definitions.keys
      end

      # Example values for the doc JSON blocks, matching the legacy generator's output: the four
      # primary counters default to 0, the percentages to "0.00%", everything else to null.
      def api_doc_json_fields(indent)
        zero = %w[count checksum_total_count checksummed_count checksum_failed_count]
          .map { |suffix| "#{status_field_prefix}_#{suffix}" }
        percentage = %w[synced_in_percentage verified_in_percentage]
          .map { |suffix| "#{status_field_prefix}_#{suffix}" }

        lines = status_fields.map do |field|
          value = if zero.include?(field)
                    '0'
                  elsif percentage.include?(field)
                    '"0.00%"'
                  else
                    'null'
                  end

          "#{indent}\"#{field}\": #{value}"
        end

        "#{lines.join(",\n")},"
      end

      def prometheus_metrics_rows
        human = @replicable_title_plural.downcase
        prefix = "geo_#{status_field_prefix}"
        [
          [prefix, "Number of #{human} on primary"],
          ["#{prefix}_checksum_total", "Number of #{human} to checksum on primary"],
          ["#{prefix}_checksummed", "Number of #{human} that successfully calculated the checksum on primary"],
          ["#{prefix}_checksum_failed", "Number of #{human} failed to calculate the checksum on primary"],
          ["#{prefix}_synced", "Number of syncable #{human} synced on secondary"],
          ["#{prefix}_failed", "Number of syncable #{human} failed to sync on secondary"],
          ["#{prefix}_registry", "Number of #{human} in the registry"],
          ["#{prefix}_verification_total", "Number of #{human} to attempt to verify on secondary"],
          ["#{prefix}_verified", "Number of #{human} successfully verified on secondary"],
          ["#{prefix}_verification_failed", "Number of #{human} that failed verification on secondary"],
          ["#{prefix}_oldest_unsynced_time", "Timestamp of the oldest unsynced #{human} on secondary"]
        ].map { |name, description| metric_row(name, description) }.join("\n")
      end

      private

      def metric_row(name, description)
        name_col = "`#{name}`".ljust(57)
        url_col = '`url`'.ljust(90)
        "| #{name_col}| Gauge     | #{@milestone} | #{url_col}| #{description} |"
      end
    end
  end
end
