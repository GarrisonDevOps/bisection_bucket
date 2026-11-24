# frozen_string_literal: true

module Search
  module Elastic
    class ReindexingTask < ApplicationRecord
      DELETE_FAILED_INDEX_AFTER = 30.days

      HUMAN_STATES = {
        "initial" => { message: "starting", color: "tip" },
        "indexing_paused" => { message: "in progress", color: "info" },
        "reindexing" => { message: "reindexing", color: "info" },
        "success" => { message: "successfully indexed", color: "success" },
        "failure" => { message: "indexing failed", color: "danger" },
        "original_index_deleted" => { message: "original index deleted", color: "info" },
        "failed_index_deleted" => { message: "failed index deleted", color: "info" }
      }.freeze

      self.table_name = 'elastic_reindexing_tasks'

      validates :max_slices_running, presence: true
      validates :slice_multiplier, presence: true
      validates :options, json_schema: { filename: 'elastic_reindexing_task_options' }

      attribute :options, ::Gitlab::Database::Type::IndifferentJsonb.new # for indifferent access

      has_many :subtasks, class_name: 'Search::Elastic::ReindexingSubtask',
        foreign_key: :elastic_reindexing_task_id, inverse_of: :elastic_reindexing_task

      enum :state, {
        initial: 0,
        indexing_paused: 1,
        reindexing: 2,
        success: 10, # states less than 10 are considered in_progress
        failure: 11,
        original_index_deleted: 12,
        failed_index_deleted: 13
      }

      scope :old_indices_scheduled_for_deletion, -> do
        where(state: :success).where.not(delete_original_index_at: nil).or(where(state: :failure))
      end

      scope :successful_indices_ready_for_cleanup, -> do
        where(state: :success)
          .where.not(delete_original_index_at: nil)
          .where('delete_original_index_at < NOW()')
      end

      scope :failed_indices_ready_for_cleanup, -> do
        where(state: :failure)
          .where(created_at: ...DELETE_FAILED_INDEX_AFTER.ago)
      end

      before_save :set_in_progress_flag

      def self.current
        where(in_progress: true).last
      end

      def self.running?
        current.present?
      end

      def self.drop_old_indices!
        successful_indices_ready_for_cleanup.find_each do |task|
          task.subtasks.each do |subtask|
            Search::Elastic::Helper.default.delete_index(index_name: subtask.index_name_from)
          end
          task.update!(state: :original_index_deleted)
        end

        failed_indices_ready_for_cleanup.find_each do |task|
          task.subtasks.each do |subtask|
            Search::Elastic::Helper.default.delete_index(index_name: subtask.index_name_to)
          end
          task.update!(state: :failed_index_deleted)
        end
      end

      def target_classes
        return ::Search::Elastic::Helper::INDEXED_CLASSES if targets.blank?

        targets.map(&:constantize)
      end

      def delete_failed_index_at
        return unless failure?

        created_at + DELETE_FAILED_INDEX_AFTER
      end

      private

      def set_in_progress_flag
        in_progress_states = self.class.states.select { |_, v| v < 10 }.keys

        self.in_progress = in_progress_states.include?(state)
      end
    end
  end
end
