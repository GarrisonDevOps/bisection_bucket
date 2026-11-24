# frozen_string_literal: true

module Vulnerabilities
  module Archival
    module Restoration
      module Tasks
        class AttachFindingsToVulnerabilities
          SQL_TEMPLATE = <<~SQL
            UPDATE
              vulnerability_occurrences
            SET
              vulnerability_id = map.vulnerability_id
            FROM
              (%{values}) AS map(id, vulnerability_id)
            WHERE
              vulnerability_occurrences.id = map.id
          SQL

          def self.execute(...)
            new(...).execute
          end

          def initialize(vulnerability_backups)
            @vulnerability_backups = vulnerability_backups
          end

          def execute
            Vulnerabilities::Finding.connection.execute(update_sql)
          end

          private

          attr_reader :vulnerability_backups

          def update_sql
            format(SQL_TEMPLATE, values: values)
          end

          def values
            Arel::Nodes::ValuesList.new(update_data).to_sql
          end

          def update_data
            vulnerability_backups.map do |backup|
              [backup.data['finding_id'], backup.original_record_identifier]
            end
          end
        end
      end
    end
  end
end
