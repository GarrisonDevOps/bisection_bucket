# frozen_string_literal: true

module SecretsManagement
  class BaseSecretsManagerMaintenanceTask < ApplicationRecord
    self.abstract_class = true

    enum :action, {
      provision: 0,
      deprovision: 1
    }

    belongs_to :user
    belongs_to :root_namespace,
      class_name: 'Namespace'

    validates :action, presence: true
    validates :root_namespace_id, presence: true
    validates :retry_count,
      numericality: {
        greater_than_or_equal_to: 0,
        only_integer: true
      }

    # Tasks that have never been processed. `last_processed_at` is NULL
    # on rows created by the AFTER DELETE trigger on the SM table, which
    # has no synchronous `perform_async`; the cron is their only
    # processor. Ruby services that create tasks set `last_processed_at`
    # to NOW() so they fall under `:stale` instead of `:unprocessed`.
    scope :unprocessed, -> { where(last_processed_at: nil) }

    # Tasks whose last processing attempt is older than `threshold`.
    # NULL rows are NOT included here; see `:unprocessed`.
    scope :stale, ->(threshold) {
      where(last_processed_at: ...threshold.ago)
    }

    # Tasks the cron should pick up: either never processed yet, or
    # processed long enough ago to be considered abandoned.
    scope :processable, ->(threshold) {
      unprocessed.or(stale(threshold))
    }

    scope :retryable, ->(max_retries) {
      where(retry_count: ...max_retries)
    }
  end
end
