# frozen_string_literal: true

module Utilization
  module BillableUsage
    # One row records that one usage export was generated on an air-gapped
    # self-managed instance, so a file later received by CustomersDot can be
    # reconciled against what the instance actually produced. The export page
    # reads it back to show when a term was last exported.
    class ExportLog < ApplicationRecord
      self.table_name = 'billable_usage_export_logs'

      CHECKSUM_FORMAT = /\A[0-9a-f]{64}\z/

      belongs_to :generated_by, class_name: 'User', optional: true

      validates :period_start, :period_end, :generated_at, :payload_checksum, presence: true
      validates :payload_checksum, format: { with: CHECKSUM_FORMAT }
      validates :record_count, numericality: { greater_than_or_equal_to: 0, only_integer: true }
      validate :period_end_on_or_after_period_start

      def self.last_generated_at_for(period_start:)
        where(period_start: period_start).maximum(:generated_at)
      end

      private

      def period_end_on_or_after_period_start
        return if period_start.blank? || period_end.blank?
        return if period_end >= period_start

        errors.add(:period_end, 'must be on or after period_start')
      end
    end
  end
end
