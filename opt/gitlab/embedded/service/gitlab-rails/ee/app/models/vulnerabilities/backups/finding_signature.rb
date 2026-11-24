# frozen_string_literal: true

module Vulnerabilities
  module Backups
    class FindingSignature < Backup
      backup_of Vulnerabilities::FindingSignature, column_mapping: { finding_id: :finding_id }

      partitioned_by :date, strategy: :monthly, retain_for: 12.months
    end
  end
end
