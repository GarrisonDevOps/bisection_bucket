# frozen_string_literal: true

module Vulnerabilities
  module Archival
    module Restoration
      module Tasks
        class RestoreRecordsFromBackup
          class << self
            def execute(...)
              new(...).execute
            end
          end

          def initialize(backup_model, parent_ids)
            @backup_model = backup_model
            @parent_ids = parent_ids
          end

          def execute
            return unless records.present?

            restore_records
          end

          private

          attr_reader :backup_model, :parent_ids

          delegate :insert_sql_template, to: :backup_model

          def restore_records
            execute_query.values.flatten
          end

          def execute_query
            backup_model.connection.execute(insert_sql)
          end

          def insert_sql
            format(insert_sql_template, values: values)
          end

          def values
            records.map(&:as_tuple).join(', ')
          end

          def records
            @records ||= backup_model.by_parents(parent_ids)
          end
        end
      end
    end
  end
end
