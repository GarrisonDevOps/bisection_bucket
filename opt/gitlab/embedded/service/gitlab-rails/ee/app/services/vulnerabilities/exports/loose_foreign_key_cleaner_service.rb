# frozen_string_literal: true

module Vulnerabilities
  module Exports
    # Upload-aware loose FK cleaner for `vulnerability_exports`. Routes the delete
    # through BatchDestroyService so the exports' uploads go with them, instead of
    # being orphaned by the generic bulk `DELETE`.
    class LooseForeignKeyCleanerService < ::LooseForeignKeys::CleanerService
      BATCH_SIZE = 500

      def execute
        export_ids = export_ids_to_clean

        BatchDestroyService.new(exports: ::Vulnerabilities::Export.id_in(export_ids)).execute

        { affected_rows: export_ids.size, table: loose_foreign_key_definition.from_table }
      end

      private

      # rubocop: disable CodeReuse/ActiveRecord -- table-specific cleanup needs the model
      # Uses model-level queries rather than @connection; both route to the sec connection.
      # No transaction, and so no `FOR UPDATE SKIP LOCKED`: the cleanup also writes to
      # `uploads` in another database. Concurrent runs are kept apart upstream, where
      # LooseForeignKeys::ProcessDeletedRecordsService claims the parent records.
      def export_ids_to_clean
        ::Vulnerabilities::Export
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
