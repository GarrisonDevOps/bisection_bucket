# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class Event < ::ApplicationRecord
      include ::Ai::DuoWorkflows::SyncWorkflowAttributes

      UUID_REGEXP = /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i

      self.table_name = :duo_workflows_events

      belongs_to :workflow, class_name: 'Ai::DuoWorkflows::Workflow'
      belongs_to :project, optional: true
      belongs_to :namespace, optional: true

      validates :event_type, presence: true
      validates :event_status, presence: true
      validates :correlation_id_value, uniqueness: { scope: :project_id }, allow_nil: true,
        format: { with: UUID_REGEXP, message: 'must be a valid UUID', if: :correlation_id_value? }

      alias_attribute :correlation_id, :correlation_id_value

      enum :event_type, { pause: 0, resume: 1, stop: 2, message: 3, response: 4, require_input: 5 }
      enum :event_status, { queued: 0, delivered: 1 }

      scope :queued, -> { where(event_status: event_statuses[:queued]) }
      scope :delivered, -> { where(event_status: event_statuses[:delivered]) }
    end
  end
end
