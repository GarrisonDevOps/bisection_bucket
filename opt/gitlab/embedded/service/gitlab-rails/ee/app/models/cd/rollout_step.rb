# frozen_string_literal: true

module Cd
  class RolloutStep < ApplicationRecord
    include BulkInsertSafe

    self.table_name = 'cd_rollout_steps'

    APPROVAL_STEP_TYPE = 'com.gitlab.cd.steps.approval'

    TERMINAL_STATES = %w[success failed skipped cancelled rejected].freeze
    FAILURE_STATES = %w[failed rejected cancelled].freeze

    belongs_to :rollout, class_name: 'Cd::Rollout', inverse_of: :rollout_steps, optional: false
    belongs_to :rollout_environment, class_name: 'Cd::RolloutEnvironment', inverse_of: :rollout_steps, optional: true
    belongs_to :organization, class_name: '::Organizations::Organization', optional: false

    populate_sharding_key :organization_id, source: :rollout

    scope :ordered, -> { order(:id) }
    scope :top_level, -> { where(parent_path: nil) }
    scope :nested, -> { where.not(parent_path: nil) }
    scope :for_rollouts, ->(rollout_ids) { where(rollout_id: rollout_ids) }
    scope :with_path, ->(path) { where(path: path) }

    validates :path, presence: true, length: { maximum: 255 }, uniqueness: { scope: :rollout_id }
    validates :parent_path, length: { maximum: 255 }
    validates :step_type, presence: true, length: { maximum: 255 }
    validates :name, length: { maximum: 255 }
    validates :error, length: { maximum: 2000 }
    validates :params, json_schema: { filename: 'cd_rollout_step_params', size_limit: 64.kilobytes }, allow_nil: true

    state_machine :state, initial: :pending do
      event :start do
        transition pending: :running, unless: :approval_step?
        transition pending: :awaiting_approval, if: :approval_step?
      end

      event :succeed do
        transition running: :success
      end

      event :fail_step do
        transition running: :failed
      end

      event :approve do
        transition awaiting_approval: :approved
      end

      event :reject do
        transition awaiting_approval: :rejected
      end

      event :skip do
        transition [:pending, :running] => :skipped, unless: :approval_step?
        transition [:pending, :awaiting_approval] => :skipped, if: :approval_step?
      end

      event :cancel do
        transition [:pending, :running] => :cancelled, unless: :approval_step?
        transition [:pending, :awaiting_approval] => :cancelled, if: :approval_step?
      end

      # BulkInsertSafe forbids after_commit/after_rollback (they don't fire per-record on
      # bulk inserts), so this uses the standalone after_all_transactions_commit instead
      # of the AfterCommitQueue pattern Cd::Rollout uses for the same kind of trigger.
      after_transition any => any do |step|
        ActiveRecord.after_all_transactions_commit do
          GraphqlTriggers.cd_rollout_step_updated(step)
        end
      end
    end

    enum :state, {
      pending: 0,
      running: 1,
      awaiting_approval: 2,
      approved: 3,
      rejected: 4,
      success: 5,
      failed: 6,
      skipped: 7,
      cancelled: 8
    }

    # Batched form of GraphQL child-step resolution: groups every nested step
    # across the given rollouts by (rollout_id, parent_path), so resolving a
    # page of stage steps takes one query regardless of how many stages it has.
    def self.nested_grouped_by_parent(rollout_ids)
      for_rollouts(rollout_ids).nested.ordered.group_by { |step| [step.rollout_id, step.parent_path] }
    end

    private

    def approval_step?
      step_type == APPROVAL_STEP_TYPE
    end
  end
end
