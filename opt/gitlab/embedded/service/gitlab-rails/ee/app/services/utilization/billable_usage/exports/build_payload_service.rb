# frozen_string_literal: true

module Utilization
  module BillableUsage
    module Exports
      class BuildPayloadService
        EXPORT_SCHEMA_VERSION = 1

        FILESIZE_LIMIT = 15.megabytes

        def initialize(period:, license: License.current, generated_at: Time.current)
          @period = period
          @license = license
          @generated_at = generated_at
        end

        def execute
          return license_missing_error unless license

          built_envelope = envelope

          over_ceiling_record = built_envelope[:records].find { |record| record[:quantity] > DailyNamespaceAggregate::MAX_QUANTITY }
          return quantity_ceiling_error(over_ceiling_record) if over_ceiling_record

          document = Checksum.seal(built_envelope)
          json = Gitlab::Json.dump(document)
          return file_too_large_error if json.bytesize > FILESIZE_LIMIT

          ServiceResponse.success(payload: { document: document, json: json })
        end

        private

        attr_reader :period, :license, :generated_at

        def envelope
          {
            export_schema_version: EXPORT_SCHEMA_VERSION,
            license_key: license.normalized_data,
            **Gitlab::BillingEvents::InstanceIdentity.to_h,
            period_start: period.start_date.iso8601,
            period_end: period.end_date.iso8601,
            generated_at: generated_at.utc.iso8601,
            record_count: records.size,
            seat_link: { records: seat_link_series.records },
            coverage: coverage.to_h,
            records: records
          }
        end

        def records
          @records ||= period.empty? ? [] : UsageRecordsService.new(period.range).execute
        end

        def seat_link_series
          @seat_link_series ||= SeatLinkSeries.new(period_start: period.start_date, period_end: period.end_date)
        end

        def coverage
          Coverage.new(
            seat_link_series: seat_link_series,
            billable_events_dates: records.map { |record| Date.iso8601(record[:timestamp]) }
          )
        end

        def quantity_ceiling_error(record)
          date = record[:timestamp].to_s[0, 10]

          ServiceResponse.error(
            message: format(
              s_('BillableUsageExport|Summed quantity for %{event_type} on %{date} exceeds the export ceiling'),
              event_type: record[:event_type], date: date
            ),
            reason: :quantity_exceeds_ceiling
          )
        end

        def license_missing_error
          ServiceResponse.error(message: s_('BillableUsageExport|No license is installed'), reason: :license_missing)
        end

        def file_too_large_error
          ServiceResponse.error(
            message: s_('BillableUsageExport|Export exceeds the file size limit'),
            reason: :file_too_large
          )
        end
      end
    end
  end
end
