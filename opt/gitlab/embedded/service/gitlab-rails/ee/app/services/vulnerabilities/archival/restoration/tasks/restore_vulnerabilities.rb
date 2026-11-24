# frozen_string_literal: true

module Vulnerabilities
  module Archival
    module Restoration
      module Tasks
        class RestoreVulnerabilities
          class << self
            def execute(...)
              new(...).execute
            end
          end

          def initialize(vulnerability_backups)
            @vulnerability_backups = vulnerability_backups
          end

          def execute
            update_updated_at_values
            restore_records
            delete_backups
            sync_elasticsearch
          end

          private

          attr_reader :vulnerability_backups

          # We are changing the `updated_at` information of the vulnerabilities
          # while restoring them from the backups; otherwise, they will get
          # archived again with the next archival execution.
          def update_updated_at_values
            vulnerability_backups.each { |backup| backup.data['updated_at'] = Time.zone.now }
          end

          def restore_records
            Vulnerabilities::Backups::Vulnerability.connection.execute(insert_sql)
          end

          def delete_backups
            Vulnerabilities::Backups::Vulnerability.by_original_ids(original_ids).delete_all
          end

          def sync_elasticsearch
            Vulnerability.current_transaction.after_commit do
              vulnerabilities = Vulnerability.id_in(original_ids)

              BulkEsOperationService.new(vulnerabilities).execute
            end
          end

          def values
            vulnerability_backups.map(&:as_tuple).join(', ')
          end

          def insert_sql
            format(Vulnerabilities::Backups::Vulnerability.insert_sql_template, values: values)
          end

          def original_ids
            vulnerability_backups.map(&:original_record_identifier)
          end
        end
      end
    end
  end
end
