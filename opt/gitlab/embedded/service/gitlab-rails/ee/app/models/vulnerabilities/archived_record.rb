# frozen_string_literal: true

module Vulnerabilities
  class ArchivedRecord < ::SecApplicationRecord
    include BulkInsertSafe
    include PartitionedTable

    self.table_name = 'vulnerability_archived_records'
    self.primary_key = :id

    partitioned_by :date, strategy: :monthly, retain_for: 36.months

    belongs_to :project, optional: false
    belongs_to :archive, class_name: 'Vulnerabilities::Archive', optional: false

    attribute :data, Gitlab::Database::Type::JsonPgSafe.new(replace_with: '\\\\\u0000')

    validates :vulnerability_identifier, presence: true
    validates :data, presence: true, json_schema: { filename: 'archived_record_data' }

    scope :by_vulnerability_ids, ->(vulnerability_ids) { where(vulnerability_identifier: vulnerability_ids) }

    def archive=(archive)
      self.date = archive&.date

      super
    end
  end
end
