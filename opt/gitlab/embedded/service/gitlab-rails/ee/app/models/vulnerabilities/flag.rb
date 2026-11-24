# frozen_string_literal: true

module Vulnerabilities
  class Flag < ::SecApplicationRecord
    self.table_name = 'vulnerability_flags'

    belongs_to :finding, class_name: 'Vulnerabilities::Finding', foreign_key: 'vulnerability_occurrence_id', inverse_of: :vulnerability_flags, optional: false
    FALSE_POSITIVE_DETECTION_STATUSES = {
      not_started: 0,
      dismissed: 1,
      detected_as_fp: 2,
      detected_as_not_fp: 3,
      failed: 4
    }.freeze

    DISMISSABLE_STATUSES = %i[detected_as_fp detected_as_not_fp].freeze

    WORKFLOW_TRIGGER_STATUSES = %i[failed detected_as_not_fp].freeze

    AI_SAST_FP_DETECTION_ORIGIN = 'ai_sast_fp_detection'
    AI_SECRET_DETECTION_FP_DETECTION_ORIGIN = 'ai_secret_detection_fp_detection'

    AI_MANAGED_ORIGINS = [
      AI_SAST_FP_DETECTION_ORIGIN,
      AI_SECRET_DETECTION_FP_DETECTION_ORIGIN
    ].freeze

    belongs_to :workflow, class_name: '::Ai::DuoWorkflows::Workflow', optional: true

    # True when a flow wrote this flag but its workflow could not be authorized; starting
    # resolution unchained would reset the chain.
    attr_accessor :parent_workflow_unresolved

    validates :origin, length: { maximum: 255 }
    validates :description, length: { maximum: 100000 }
    validates :flag_type, presence: true, uniqueness: { scope: [:vulnerability_occurrence_id, :origin] }
    validates :confidence_score, inclusion: { in: 0.0..1.0 }

    enum :flag_type, {
      false_positive: 0
    }

    enum :status, FALSE_POSITIVE_DETECTION_STATUSES
    scope :by_finding_id, ->(finding_ids) { where(finding: finding_ids) }
    scope :latest, -> { order(updated_at: :desc) }

    after_commit :trigger_resolution_workflow, on: [:create, :update], if: :should_trigger_resolution_workflow?

    scope :with_associations, -> do
      includes(
        finding: [
          :project,
          { vulnerability: [:group, :author, :project] }
        ]
      )
    end

    scope :with_status, ->(status) { where(status: statuses[status]) }
    scope :last_false_positive_per_finding, -> {
      joins(<<~SQL.squish)
        INNER JOIN (
          SELECT vulnerability_occurrence_id, MAX(id) AS max_id
          FROM vulnerability_flags AS lpf
          WHERE lpf.flag_type = #{flag_types[:false_positive]}
          GROUP BY vulnerability_occurrence_id
        ) AS last_flags
        ON last_flags.vulnerability_occurrence_id = vulnerability_flags.vulnerability_occurrence_id
        AND last_flags.max_id = vulnerability_flags.id
      SQL
    }

    def self.pluck_with_limit(size, *columns)
      limit(size).pluck(*columns)
    end

    def initialize(attributes)
      attributes = attributes.to_h if attributes.respond_to?(:to_h)
      super
    end

    def dismissable?
      status.to_sym.in?(DISMISSABLE_STATUSES)
    end

    def triggers_resolution_workflow?
      required_confidence = ::Vulnerabilities::AiTriage::Eligibility
        .configuration_for(finding.project, :sast_vulnerability_resolution)[:false_positive_confidence]

      return status.to_sym.in?(WORKFLOW_TRIGGER_STATUSES) if required_confidence.blank?
      return detected_as_fp? if required_confidence == 'likely_false_positive'

      detected_as_not_fp?
    end

    def eligible_for_resolution_workflow?(caller_context = resolution_workflow_caller_context)
      return false unless origin == AI_SAST_FP_DETECTION_ORIGIN
      return false unless triggers_resolution_workflow?
      return false unless finding.resolution_workflow_enabled?
      return false unless finding.eligible_for_resolution_workflow?
      return false unless default_context?

      duo_workflow_user_available?(caller_context)
    end

    # Nil unless a flow wrote this flag with chaining enabled. Only read for the save that wrote it:
    # the worker takes the parent from its arguments, as a later write can change this row.
    def resolution_workflow_caller_context
      return unless workflow
      # A chain needs a human root, so a flag from an automatic run starts an automatic resolution instead.
      return if ::Ai::DuoWorkflows::Workflow::AUTONOMOUS_TRIGGER_SOURCES.include?(workflow.trigger_source)
      return unless Feature.enabled?(:ai_flow_trigger_chaining, finding.project.root_ancestor)

      ::Ai::FlowTriggers::CallerContext.new(parent_workflow: workflow)
    end

    private

    # The resolution workflow always runs against the default branch, so
    # findings from non-default contexts would be resolved on the wrong ref.
    # Vulnerabilities created from merge request security findings have no
    # tracked context, and are not present on the default branch.
    def default_context?
      return false unless finding.vulnerability&.present_on_default_branch?

      context = finding.project_tracked_context

      context.nil? || context.is_default?
    end

    def auto_run_resolution_workflow?
      ::Vulnerabilities::AiTriage::Eligibility.auto_run?(finding.vulnerability, :sast_vulnerability_resolution)
    end

    def trigger_resolution_workflow
      caller_context = resolution_workflow_caller_context

      if caller_context
        ::Vulnerabilities::TriggerResolutionWorkflowWorker.perform_async(id, nil, caller_context.parent_workflow.id)
      else
        ::Vulnerabilities::TriggerResolutionWorkflowWorker.perform_async(id)
      end
    end

    def should_trigger_resolution_workflow?
      return false unless saved_change_to_id? || saved_change_to_status?
      return false if parent_workflow_unresolved
      return false unless eligible_for_resolution_workflow?
      return false unless auto_run_resolution_workflow?

      # Automatic SAST false positive detection runs for newly created eligible vulnerabilities.
      # Automatic resolution can be incorrectly skipped only if all of these happen:
      # - The automatic detection workflow is still running.
      # - The same finding is added to a bulk detection execution.
      # - The automatic result arrives after the bulk execution starts.
      # We currently accept this rare race since resolution can still be triggered manually,
      # and avoiding it would require a larger redesign.
      !part_of_bulk_sast_fp_execution?
    end

    def duo_workflow_user_available?(caller_context)
      user = caller_context ? caller_context.root_human : finding.vulnerability.author
      return false unless user

      Ability.allowed?(user, :duo_workflow, finding.project)
    end

    def part_of_bulk_sast_fp_execution?
      execution = ::Vulnerabilities::BulkDuoWorkflow::ExecutionState.latest(
        project_id: finding.project_id,
        workflow: ::Vulnerabilities::TriggerFalsePositiveDetectionWorkflowWorker::WORKFLOW_DEFINITION
      )

      return false unless execution

      execution.contains_item?(finding.uuid)
    end
  end
end
