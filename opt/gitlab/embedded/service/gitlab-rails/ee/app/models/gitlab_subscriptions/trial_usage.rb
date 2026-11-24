# frozen_string_literal: true

module GitlabSubscriptions
  class TrialUsage < ApplicationRecord
    include PartitionedTable

    self.table_name = 'trial_usages'
    self.primary_key = :id

    partitioned_by :trial_ends_on, strategy: :monthly, retain_for: 24.months

    belongs_to :namespace, optional: false

    validates :trial_starts_on, :trial_ends_on, :compute_minutes_month, presence: true
    validates :trial_ends_on, uniqueness: { scope: :namespace_id }
    validates :trial_ends_on, comparison: { greater_than: :trial_starts_on }, if: :trial_starts_on
    validates :trial_type, length: { maximum: 255 }
    validates :max_seats_used, :compute_minutes_used,
      numericality: { only_integer: true, greater_than_or_equal_to: 0 }
    validates :credits_used, numericality: { greater_than_or_equal_to: 0 }, allow_nil: true

    scope :for_namespace, ->(namespace) { where(namespace: namespace) }

    def self.find_for_trial(namespace_id, trial_ends_on)
      find_by(namespace_id: namespace_id, trial_ends_on: trial_ends_on)
    end
  end
end
