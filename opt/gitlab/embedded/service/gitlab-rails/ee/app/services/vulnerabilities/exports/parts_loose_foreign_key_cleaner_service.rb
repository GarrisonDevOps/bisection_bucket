# frozen_string_literal: true

module Vulnerabilities
  module Exports
    # Upload-aware loose FK cleaner for `vulnerability_export_parts`. The generic
    # bulk `DELETE` would drop the rows and orphan the uploads they own.
    class PartsLooseForeignKeyCleanerService < ::LooseForeignKeys::CleanerService
      BATCH_SIZE = 500

      def execute
        part_ids = part_ids_to_clean
        deleted_rows = 0

        unless part_ids.empty?
          parts = ::Vulnerabilities::Export::Part.id_in(part_ids)
          Upload.destroy_for_associations!(parts)
          deleted_rows = parts.delete_all
        end

        { affected_rows: deleted_rows, table: loose_foreign_key_definition.from_table }
      end

      private

      # rubocop: disable CodeReuse/ActiveRecord -- table-specific cleanup needs the model
      # Uses model-level queries rather than @connection; both route to the sec connection.
      # No transaction, and so no `FOR UPDATE SKIP LOCKED`: the cleanup also writes to
      # `uploads` in another database. Concurrent runs are kept apart upstream, where
      # LooseForeignKeys::ProcessDeletedRecordsService claims the parent records.
      def part_ids_to_clean
        ::Vulnerabilities::Export::Part
          .where(loose_foreign_key_definition.column => parent_record_ids)
          .limit(batch_size)
          .pluck_primary_key
      end
      # rubocop: enable CodeReuse/ActiveRecord

      def parent_record_ids
        deleted_parent_records.map(&:primary_key_value)
      end

      def batch_size
        loose_foreign_key_definition.options[:delete_limit] || BATCH_SIZE
      end
    end
  end
end
