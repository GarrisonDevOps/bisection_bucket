# frozen_string_literal: true

module Ai
  module ActiveContext
    class Task < ApplicationRecord
      self.table_name = :ai_active_context_tasks

      attribute :retries_left, default: 3
      attribute :params, default: -> { {} }

      enum :status, {
        pending: 0,
        in_progress: 1,
        completed: 10,
        failed: 255
      }

      belongs_to :connection, class_name: 'Ai::ActiveContext::Connection'
      belongs_to :depends_on, class_name: 'Ai::ActiveContext::Task', optional: true, inverse_of: :dependents
      has_many :dependents, class_name: 'Ai::ActiveContext::Task', foreign_key: :depends_on_id, inverse_of: :depends_on

      validates :name, presence: true, length: { maximum: 255 }
      validates :status, presence: true
      validates :retries_left, numericality: { greater_than_or_equal_to: 0 }
      validates :params, json_schema: { filename: 'ai_active_context_task_params', size_limit: 16.kilobytes }
      validate :validate_zero_retries_left, if: -> { retries_left == 0 }

      scope :processable, -> {
        pending_or_in_progress
          .where(
            'ai_active_context_tasks.depends_on_id IS NULL OR EXISTS (
              SELECT 1 FROM ai_active_context_tasks dep
              WHERE dep.id = ai_active_context_tasks.depends_on_id
              AND dep.status = ?
            )',
            statuses[:completed]
          )
          .order(:created_at)
      }

      scope :with_active_connection, -> {
        joins(:connection).where(connection: { active: true })
      }

      scope :pending_or_in_progress, -> { where(status: [:pending, :in_progress]) }
      scope :by_name, ->(name) { where(name: name) }
      scope :by_collection_name, ->(collection_name) do
        where("params->>'collection' = ?", collection_name)
      end

      def self.current
        with_active_connection.processable.first
      end

      def self.latest_by_name_and_collection(name:, collection_name:)
        with_active_connection.by_name(name).by_collection_name(collection_name).order(id: :desc).first
      end

      def mark_as_started!
        update!(
          status: :in_progress,
          started_at: Time.zone.now
        )
      end

      def mark_as_completed!
        update!(
          status: :completed,
          completed_at: Time.zone.now
        )
      end

      def mark_as_failed!(error)
        update!(
          status: :failed,
          retries_left: 0,
          error_message: "#{error.class}: #{error.message}"[0, 1024]
        )

        fail_dependents!
      end

      def fail_dependents!
        self.class.transaction do
          recursively_fail_dependents!
        end
      end

      def decrease_retries!(error)
        if retries_left == 1
          mark_as_failed!(error)
        else
          update!(retries_left: retries_left - 1)
        end
      end

      def recursively_fail_dependents!
        dependents.pending.find_each do |dependent|
          dependent.update!(
            status: :failed,
            retries_left: 0,
            error_message: "Dependency '#{name}' failed"
          )
          dependent.recursively_fail_dependents!
        end
      end

      private

      def validate_zero_retries_left
        errors.add(:retries_left, 'can only be 0 when status is failed') unless failed?
      end
    end
  end
end
