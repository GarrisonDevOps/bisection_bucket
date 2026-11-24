# frozen_string_literal: true

module AuditEvents
  class ExportCsvService
    # Bounds how many records are hydrated per round trip, not the size of the export.
    BATCH_SIZE = 1_000

    def initialize(params = {})
      @params = params
    end

    def csv_data
      csv_builder.render
    end

    private

    def csv_builder
      @csv_builder ||= CsvBuilder::Stream.new(data, header_to_value_hash)
    end

    # Audit events are stored in one table per scope, so rows arrive from a UNION
    # rather than a single relation that `each_batch` could walk. Paging the finder
    # by keyset cursor keeps the export in the same order as the audit events UI.
    def data
      Enumerator.new do |yielder|
        cursor = nil

        loop do
          result = fetch_page(cursor)
          records = result[:records]
          break if records.empty?

          # `author` and `entity` are BatchLoader backed and read once per row, so
          # they have to be resolved a page at a time.
          ::Gitlab::Audit::Events::Preloader.preload!(records)
          records.each { |record| yielder << record }
          ::BatchLoader::Executor.clear_current

          cursor = result[:cursor_for_next_page]
          break if cursor.blank?
        end
      end
    end

    def fetch_page(cursor)
      ::AuditEvents::CombinedAuditEventFinder.new(
        params: @params.merge(pagination: 'keyset', per_page: BATCH_SIZE, cursor: cursor)
      ).execute
    end

    def header_to_value_hash
      {
        'ID' => 'id',
        'Author ID' => 'author_id',
        'Author Name' => 'author_name',
        'Author Email' => ->(event) { event.author.try(:email) },
        'Entity ID' => 'entity_id',
        'Entity Type' => 'entity_type',
        'Entity Path' => 'entity_path',
        'Target ID' => 'target_id',
        'Target Type' => 'target_type',
        'Target Details' => 'target_details',
        'Action' => ->(event) { Audit::Details.humanize(event.details) },
        'IP Address' => 'ip_address',
        'Created At (UTC)' => ->(event) { event.created_at.utc.iso8601 }
      }
    end
  end
end
