# frozen_string_literal: true

module Vulnerabilities
  module Removal
    module Tasks
      class AbstractTask
        include Gitlab::Utils::StrongMemoize

        class << self
          attr_accessor :model
        end

        def initialize(parent_ids, backup_date)
          @parent_ids = parent_ids
          @backup_date = backup_date
        end

        def execute
          loop do
            rows = delete_batch

            break if rows.empty?

            create_backup_records(rows) if backup?
          end
        end

        private

        attr_reader :parent_ids, :backup_date

        delegate :model, to: :'self.class', private: true
        delegate :backup_model, to: :model, private: true

        def delete_batch
          relation.delete_all_returning(*returning)
        end

        def returning
          [:id] unless backup?
        end

        def backup?
          backup_date && backup_model
        end
        strong_memoize_attr :backup?

        def create_backup_records(deleted_rows)
          BackupService.execute(backup_model, backup_date, deleted_rows)
        end
      end
    end
  end
end
