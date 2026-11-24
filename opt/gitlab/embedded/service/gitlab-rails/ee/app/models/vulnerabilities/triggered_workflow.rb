# frozen_string_literal: true

module Vulnerabilities
  class TriggeredWorkflow < ::SecApplicationRecord
    self.table_name = 'vulnerability_triggered_workflows'

    belongs_to :vulnerability_occurrence, class_name: 'Vulnerabilities::Finding'
    belongs_to :workflow, class_name: 'Ai::DuoWorkflows::Workflow'

    validates_presence_of :vulnerability_occurrence, :workflow
    validates :workflow_name, presence: true
    validate :vulnerability_workflow_belongs_to_same_project

    before_validation :assign_project_id

    WORKFLOW_NAMES = {
      sast_fp_detection: 0,
      resolve_sast_vulnerability: 1,
      secrets_fp_detection: 2
    }.freeze

    # Maps the `workflow_definition` string used by the DAP API to the
    # `workflow_name` enum value stored on this join row. Used to back-fill
    # the link when a user triggers one of these workflows directly via the
    # API (the automated/flag-driven paths create the link in their workers).
    WORKFLOW_DEFINITIONS_TO_NAMES = {
      'resolve_sast_vulnerability/v1' => :resolve_sast_vulnerability,
      'sast_fp_detection/v1' => :sast_fp_detection,
      'secrets_fp_detection/v1' => :secrets_fp_detection
    }.freeze

    enum :workflow_name, WORKFLOW_NAMES

    scope :with_workflow_name, ->(workflow_name) { where(workflow_name: workflow_name) }
    scope :created_at_or_before, ->(time) { where(created_at: ..time) }
    scope :order_by_created_at_desc, -> { order(created_at: :desc, id: :desc) }

    private

    def assign_project_id
      self.project_id ||= vulnerability_occurrence&.project_id
    end

    def vulnerability_workflow_belongs_to_same_project
      return unless vulnerability_occurrence
      return unless workflow

      return if vulnerability_occurrence.project_id == workflow.project_id

      errors.add(:workflow, _("must belong to the same project as the vulnerability"))
    end
  end
end
