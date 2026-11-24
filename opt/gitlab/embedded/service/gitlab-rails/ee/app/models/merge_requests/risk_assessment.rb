# frozen_string_literal: true

module MergeRequests
  class RiskAssessment < ApplicationRecord
    include AfterCommitQueue
    include ShaAttribute

    SCHEMA_SIZE_LIMIT = 64.kilobytes

    sha_attribute :diff_sha

    belongs_to :merge_request, optional: false, inverse_of: :risk_assessment
    belongs_to :duo_workflow, class_name: 'Ai::DuoWorkflows::Workflow', optional: true

    has_many :risk_outcomes, class_name: 'MergeRequests::RiskOutcome',
      inverse_of: :risk_assessment

    validates :merge_request_id, uniqueness: true
    validates :project_id, presence: true
    validates :status, presence: true
    validates :diff_sha, presence: true, length: { maximum: 64 }

    validates :score, :confidence,
      numericality: {
        only_integer: true,
        greater_than_or_equal_to: ::Gitlab::Duo::RiskAssessment::Thresholds::MIN_SCORE,
        less_than_or_equal_to: ::Gitlab::Duo::RiskAssessment::Thresholds::MAX_SCORE
      },
      allow_nil: true

    validates :scoring_function_version, length: { maximum: 20 }
    validates :rationale, length: { maximum: 2048 }

    validates :classification,
      json_schema: {
        filename: 'merge_requests_risk_assessment_classification',
        size_limit: SCHEMA_SIZE_LIMIT
      }
    validates :signal_breakdown,
      json_schema: {
        filename: 'merge_requests_risk_assessment_signal_breakdown',
        size_limit: SCHEMA_SIZE_LIMIT
      }

    populate_sharding_key :project_id, source: :merge_request

    def self.ensure_for!(merge_request)
      merge_request.risk_assessment ||
        merge_request.create_risk_assessment!(diff_sha: merge_request.diff_head_sha)
    rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordInvalid
      merge_request.reset.risk_assessment || raise
    end

    def risk_tier
      ::Gitlab::Duo::RiskAssessment::Thresholds.risk_tier_for(score)
    end

    def confidence_tier
      ::Gitlab::Duo::RiskAssessment::Thresholds.confidence_tier_for(confidence)
    end

    state_machine :status, initial: :pending do
      state :pending, value: 0
      state :queued, value: 1
      state :complete, value: 2
      state :failed, value: 3
      state :scoring, value: 4

      event :enqueue do
        transition %i[pending complete failed] => :queued
      end

      event :refresh do
        transition all => :scoring,
          if: ->(assessment, *args) { assessment.refreshable_for?(args.first) }
      end

      # :complete lets a newer revision's score replace an older one; see #accepts_score_for?.
      event :finish do
        transition %i[scoring complete] => :complete
      end

      # Deliberately excludes :complete, so a session hook arriving late cannot
      # erase a result that was already scored.
      event :mark_failed do
        transition %i[pending queued scoring] => :failed
      end

      # refresh(diff_sha, classification, workflow_id) - the event args aren't
      # declared on the event itself, so they're read back off the transition.
      after_transition on: :refresh do |assessment, transition|
        diff_sha, classification, workflow_id = transition.args
        assessment.enqueue_risk_score_calculation(diff_sha, classification, workflow_id)
      end
    end

    # Guards `refresh` so an out-of-order submission can't regress a newer result.
    # Callers holding a row lock get this checked against the locked row, which is
    # what makes concurrent submissions safe.
    def refreshable_for?(incoming_diff_sha)
      incoming_ordinal = revision_ordinal(incoming_diff_sha)
      # A revision that isn't in this merge request's history can't be placed
      # relative to the current one, so it's refused rather than guessed at.
      return false unless incoming_ordinal

      current_ordinal = revision_ordinal(diff_sha)
      # Nothing to be stale against: either a brand-new assessment, or the diff it
      # was built from has since been pruned. Fail open rather than wedge the row.
      return true unless current_ordinal

      incoming_ordinal >= current_ordinal
    end

    # Score jobs from overlapping submissions finish in any order, and diff_sha is the last revision
    # scored. A row waiting on a score takes a revision at least that new; a complete row only a newer one.
    def accepts_score_for?(incoming_diff_sha)
      return false unless can_finish?
      return false if complete? && incoming_diff_sha == diff_sha

      refreshable_for?(incoming_diff_sha)
    end

    def enqueue_risk_score_calculation(diff_sha, classification, workflow_id)
      run_after_commit do
        ::Ai::RiskAssessment::CalculateScoreWorker.perform_async(
          merge_request_id, diff_sha, classification, workflow_id
        )
      end
    end

    private

    # diff_sha values aren't ordered on their own (a rebase or amend produces a SHA
    # with no ancestry relation to the one it replaces), so ordering is delegated to
    # the merge request's own push history.
    def revision_ordinal(sha)
      merge_request.merge_request_diffs.ordinal_for(sha)
    end
  end
end
