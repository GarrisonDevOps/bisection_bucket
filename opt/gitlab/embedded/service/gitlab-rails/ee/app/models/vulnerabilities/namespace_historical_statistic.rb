# frozen_string_literal: true

module Vulnerabilities
  class NamespaceHistoricalStatistic < ::SecApplicationRecord
    include ::Namespaces::Traversal::Traversable

    self.table_name = 'vulnerability_namespace_historical_statistics'

    belongs_to :namespace
    validates :total, numericality: { greater_than_or_equal_to: 0 }
    validates :critical, numericality: { greater_than_or_equal_to: 0 }
    validates :high, numericality: { greater_than_or_equal_to: 0 }
    validates :medium, numericality: { greater_than_or_equal_to: 0 }
    validates :low, numericality: { greater_than_or_equal_to: 0 }
    validates :unknown, numericality: { greater_than_or_equal_to: 0 }
    validates :info, numericality: { greater_than_or_equal_to: 0 }
    validates :date, presence: true
    validates :traversal_ids, presence: true
    validates :letter_grade, presence: true

    enum :letter_grade, Vulnerabilities::Statistic.letter_grades

    scope :by_direct_group, ->(group) { where(namespace: group) }
    scope :older_than, ->(days:) {
      where('"vulnerability_namespace_historical_statistics"."date" < (now() - interval ?)', "#{days} days")
    }

    scope :for_namespace_and_descendants, ->(namespace) do
      within(namespace.traversal_ids)
    end

    scope :between_dates, ->(start_date, end_date) { where(date: start_date..end_date) }
    scope :aggregated_by_date, -> do
      select(
        arel_table[:date],
        arel_table[:total].sum.as('total'),
        *::Enums::Vulnerability.severity_levels.map { |severity, _| arel_table[severity].sum.as(severity.to_s) }
      )
    end
    scope :grouped_by_date, ->(sort = :asc) do
      group(:date)
        .order(date: sort)
    end
  end
end
