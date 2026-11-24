# frozen_string_literal: true

module Security
  class ScheduledPipelineExecutionPolicyTestRun < ApplicationRecord
    include Ci::Partitionable::AssociationFinder

    self.table_name = 'security_scheduled_pipeline_execution_policy_test_runs'

    belongs_to :security_policy, class_name: 'Security::Policy',
      inverse_of: :scheduled_pipeline_execution_policy_test_runs
    belongs_to :project
    belongs_to :pipeline, class_name: 'Ci::Pipeline'
    partitionable_belongs_to_loader :pipeline

    validates :security_policy, :project, presence: true
    validates :pipeline_id, uniqueness: true, allow_nil: true
    validate :security_policy_is_pipeline_execution_schedule_policy

    PENDING_TIMEOUT = 1.hour.freeze
    RUNNING_TIMEOUT = 24.hours.freeze

    enum :state, { running: 0, complete: 1, failed: 2, pending: 3, creating: 4 }, default: :pending

    scope :for_pipeline_id, ->(pipeline_id) { where(pipeline_id: pipeline_id) }
    scope :stale_pending, -> { pending.where(created_at: ...PENDING_TIMEOUT.ago) }
    scope :stale_running, -> { running.where(created_at: ...RUNNING_TIMEOUT.ago) }
    scope :stale, -> { stale_pending.or(stale_running).order(created_at: :asc) }
    scope :preload_project, -> { includes(:project) }
    scope :for_policy, ->(policy) { where(security_policy: policy) }
    scope :preload_pipeline, -> { with_partition_aware_preload.preload(:pipeline) }
    scope :with_associations, -> {
      preload_pipeline
        .preload(project: :route, security_policy: :security_policy_management_project)
        .order(id: :desc)
    }

    def self.mark_as_failed(ids:, error_message:, expected_state:)
      return 0 if ids.empty?

      id_in(ids).where(state: expected_state).update_all(
        state: :failed,
        error_message: error_message,
        updated_at: Time.current
      )
    end

    delegate :started_at, :finished_at, :duration, to: :pipeline, allow_nil: true

    before_save :truncate_error_message

    # Atomic update ensures only one concurrent worker can claim the test run.
    def claim_for_pipeline_creation
      self.class.where(id: id, state: :pending).update_all(state: :creating, updated_at: Time.current) == 1
    end

    def mark_as_failed!(error_message = nil)
      update!(error_message: error_message, state: :failed)
    end

    def completed?
      complete? || failed?
    end

    private

    def truncate_error_message
      self.error_message = error_message&.truncate(255, omission: '')
    end

    def security_policy_is_pipeline_execution_schedule_policy
      return unless security_policy

      return if security_policy.type_pipeline_execution_schedule_policy?

      errors.add(:security_policy, _('must be a pipeline execution schedule policy'))
    end
  end
end
