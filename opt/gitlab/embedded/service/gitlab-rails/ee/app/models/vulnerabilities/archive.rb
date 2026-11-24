# frozen_string_literal: true

module Vulnerabilities
  class Archive < ::SecApplicationRecord
    include PartitionedTable

    self.table_name = 'vulnerability_archives'
    self.primary_key = :id

    partitioned_by :date, strategy: :monthly, retain_for: 36.months

    belongs_to :project, optional: false
    has_many :archived_records, class_name: 'Vulnerabilities::ArchivedRecord'

    validates :date, presence: true, uniqueness: { scope: :project_id }
    validates :archived_records_count, numericality: { only_integer: true, greater_than_or_equal_to: 0 }

    delegate :year, :month, to: :date, allow_nil: true

    def date=(value)
      value = value.beginning_of_month if value

      super
    end
  end
end
