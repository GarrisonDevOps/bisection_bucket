# frozen_string_literal: true

module Vulnerabilities
  module Backups
    class FindingEvidence < Backup
      backup_of Vulnerabilities::Finding::Evidence, column_mapping: { vulnerability_occurrence_id: :finding_id }

      partitioned_by :date, strategy: :monthly, retain_for: 12.months
    end
  end
end
