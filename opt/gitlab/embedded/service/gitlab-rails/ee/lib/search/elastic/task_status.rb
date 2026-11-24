# frozen_string_literal: true

module Search
  module Elastic
    class TaskStatus
      attr_reader :raw_hash, :counts, :error_type, :error_reason, :failures

      EXPECTED_COUNT_KEYS = %w[total created updated deleted].freeze

      def initialize(task_id:)
        helper = ::Search::Elastic::Helper.default
        task_status = helper.task_status(task_id: task_id).with_indifferent_access

        response = task_status.fetch(:response, {})

        @counts = response.slice(:total, :created, :updated, :deleted)
        @completed = task_status[:completed]
        @error_type = task_status.dig(:error, :type)
        @error_reason = task_status.dig(:error, :reason)
        @failures = response.fetch(:failures, {})
        @raw_hash = task_status.to_hash
      end

      def completed?
        completed
      end

      def totals_match?
        return false unless (EXPECTED_COUNT_KEYS - counts.keys).empty?

        counts[:total] == (counts[:created] + counts[:updated] + counts[:deleted])
      end

      def error?
        error_type.present? || error_reason.present? || failures.present?
      end

      private

      attr_reader :completed
    end
  end
end
