# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module SessionCredits
      # Writes one CustomersDot `sessions` page to the session enrichments table. The table
      # is a ReplacingMergeTree versioned by `updated_at`, so every column is written on
      # every row and the clock written is CustomersDot's `updatedAt`, never ours.
      class IngestService
        InvalidRow = Class.new(StandardError)

        TABLE_NAME = 'duo_workflow_session_enrichments'
        CSV_MAPPING = {
          workflow_id: ->(row) { row[:workflow_id] },
          credits_used: ->(row) { row[:credits_used] },
          model_used: ->(row) { row[:model_used] },
          credits_by_model: ->(row) { row[:credits_by_model] },
          updated_at: ->(row) { row[:updated_at] }
        }.freeze
        INSERT_QUERY = <<~SQL.squish
          INSERT INTO #{TABLE_NAME} (#{CSV_MAPPING.keys.join(',')})
          FORMAT CSV
        SQL

        def initialize(nodes:)
          @nodes = Array(nodes)
        end

        def execute
          rows = nodes.filter_map { |node| build_row(node) }
          max_us = max_updated_at_us

          ServiceResponse.success(payload: { rows_written: insert(rows), max_updated_at_us: max_us })
        rescue InvalidRow => e
          ServiceResponse.error(message: e.message, reason: :invalid_rows)
        end

        private

        attr_reader :nodes

        # Null credits means CustomersDot has nothing for the session yet; an explicit 0 is a
        # correction it sends once and must be written.
        def build_row(node)
          return if node[:creditsUsed].nil?

          {
            workflow_id: workflow_id_from(node[:workflowId]),
            credits_used: decimal(node[:creditsUsed]),
            model_used: Array(node[:modelsUsed]).first.to_s,
            credits_by_model: map_literal(node[:creditsByModel]),
            updated_at: updated_at(node).strftime('%Y-%m-%d %H:%M:%S.%6N')
          }
        end

        def updated_at(node)
          Time.iso8601(node[:updatedAt].to_s).utc
        rescue ArgumentError
          raise InvalidRow, "updatedAt #{node[:updatedAt].inspect} is not an ISO 8601 time"
        end

        def workflow_id_from(value)
          id = value.to_s[/\d+\z/].to_i
          raise InvalidRow, "workflowId #{value.inspect} has no numeric id" unless id > 0

          id
        end

        def decimal(value)
          BigDecimal(value.to_s).to_s('F')
        rescue ArgumentError, TypeError
          raise InvalidRow, "credits #{value.inspect} is not a number"
        end

        def map_literal(entries)
          pairs = Array(entries).map do |entry|
            "#{::ClickHouse::Client::Quoting.quote(entry[:model].to_s)}:#{decimal(entry[:creditsUsed])}"
          end

          "{#{pairs.join(',')}}"
        end

        # From every node, not only written rows: a window holding only null-credit
        # sessions must still move the cursor, or the next tick re-reads it forever.
        def max_updated_at_us
          nodes.map { |node| (updated_at(node).to_r * 1_000_000).to_i }.max
        end

        def insert(rows)
          return 0 if rows.empty?

          CsvBuilder::Gzip.new(rows, CSV_MAPPING).render do |tempfile, rows_written|
            File.open(tempfile.path) { |file| ::ClickHouse::Client.insert_csv(INSERT_QUERY, file, :main) }

            rows_written
          end
        end
      end
    end
  end
end
