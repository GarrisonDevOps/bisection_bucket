# frozen_string_literal: true

module Vulnerabilities
  module Removal
    class BackupService
      def self.execute(...)
        new(...).execute
      end

      def initialize(backup_model, date, deleted_rows, extra: {})
        @backup_model = backup_model
        @date = date
        @deleted_rows = deleted_rows
        @extra = extra
      end

      def execute
        backup_model.bulk_insert!(backup_objects)
      end

      private

      attr_reader :backup_model, :date, :deleted_rows, :extra

      delegate :column_mappings, to: :backup_model, private: true

      def backup_objects
        deleted_rows.map { |row| object_from_row(row) }
      end

      def object_from_row(row)
        record_data = prepare_attributes(row)

        backup_model.new(**record_data, date: date)
      end

      def prepare_attributes(row)
        data = initiate_data_for(row)

        execute_mapping(data, row)

        data
      end

      def initiate_data_for(row)
        {
          created_at: timestamp,
          updated_at: timestamp,
          data: row,
          **extra
        }
      end

      def execute_mapping(data, row)
        column_mappings.each do |column_name_on_prod_data, column_name_on_backup_data|
          data[column_name_on_backup_data] = row.delete(column_name_on_prod_data.to_s)
        end
      end

      def timestamp
        @timestamp ||= Time.zone.now
      end
    end
  end
end
