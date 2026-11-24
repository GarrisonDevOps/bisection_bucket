# frozen_string_literal: true

module Vulnerabilities
  module Archival
    module Restoration
      module Tasks
        class UpdateArchives
          SQL_TEMPLATE = <<~SQL
            UPDATE
              vulnerability_archives
            SET
              archived_records_count = archived_records_count - map.removed_records_count
            FROM
              (%{values}) AS map(archive_id, removed_records_count)
            WHERE
              vulnerability_archives.id = map.archive_id
          SQL

          def self.execute(...)
            new(...).execute
          end

          def initialize(restored_vulnerability_ids)
            @restored_vulnerability_ids = restored_vulnerability_ids
          end

          def execute
            return unless archived_records.present?

            delete_archived_records
            update_archive_statistics
          end

          private

          attr_reader :restored_vulnerability_ids

          delegate :connection, to: SecApplicationRecord

          def delete_archived_records
            archived_records.spawn.delete_all
          end

          def update_archive_statistics
            connection.execute(statistics_update_sql)
          end

          def statistics_update_sql
            format(SQL_TEMPLATE, values: values)
          end

          def values
            Arel::Nodes::ValuesList.new(archive_statistics_data).to_sql
          end

          def archive_statistics_data
            archived_records.map(&:archive_id).tally.to_a
          end

          def archived_records
            @archived_records ||= Vulnerabilities::ArchivedRecord.by_vulnerability_ids(restored_vulnerability_ids)
          end
        end
      end
    end
  end
end
