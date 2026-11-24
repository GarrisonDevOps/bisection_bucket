# frozen_string_literal: true

module Utilization
  module BillableUsage
    class DailyTotal < ApplicationRecord
      self.table_name = 'billable_usage_daily_totals'

      UNIQUE_BY = %i[usage_date event_type feature_qualified_name operation_type].freeze

      validates :source_updated_at, :usage_date, :event_type, :unit_of_measure, :feature_qualified_name,
        :quantity, :events_count, :schema_version, presence: true
      validates :quantity, numericality: { greater_than_or_equal_to: 0 }
      validates :events_count, numericality: { greater_than_or_equal_to: 0, only_integer: true }
      validates :event_type, :feature_qualified_name, length: { maximum: 255 }
      validates :unit_of_measure, length: { maximum: 64 }
      validates :operation_type, length: { maximum: 64 }, allow_nil: true

      scope :in_period, ->(range) { where(usage_date: range) }

      scope :ordered_for_export, -> {
        order(*UNIQUE_BY.map { |column| arel_table[column].asc.nulls_first })
      }

      def self.watermark
        maximum(:source_updated_at)
      end
    end
  end
end
