# frozen_string_literal: true

module Vulnerabilities
  module Backups
    class FindingIdentifier < Backup
      backup_of Vulnerabilities::FindingIdentifier, column_mapping: { occurrence_id: :finding_id }

      partitioned_by :date, strategy: :monthly, retain_for: 12.months
    end
  end
end
