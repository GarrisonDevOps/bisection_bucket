# frozen_string_literal: true

module Vulnerabilities
  module Backups
    class Finding < Backup
      class << self
        # We restore findings first which has foreign key constraint to
        # the vulnerabilities table. If we don't remove the vulnerability IDs
        # from the insert SQL, the query fails as the related vulnerabilities
        # are not in the table yet.
        def ordered_column_names
          super - [:vulnerability_id]
        end

        private

        # Template method used by the parent class.
        def on_conflict
          'ON CONFLICT(uuid) DO NOTHING'
        end
      end

      backup_of Vulnerabilities::Finding, column_mapping: { vulnerability_id: :vulnerability_id }

      partitioned_by :date, strategy: :monthly, retain_for: 12.months

      scope :by_vulnerabilities, ->(vulnerabilities) { where(vulnerability_id: vulnerabilities) }

      private

      # This is the same FK problem.
      def all_values
        super[1..]
      end
    end
  end
end
