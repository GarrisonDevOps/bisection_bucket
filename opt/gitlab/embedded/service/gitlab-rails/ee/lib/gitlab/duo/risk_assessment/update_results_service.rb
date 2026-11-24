# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      class UpdateResultsService
        def initialize(merge_request:, classification:, diff_sha:, workflow_id:)
          @merge_request = merge_request
          @classification = (classification || {}).deep_stringify_keys
          @diff_sha = diff_sha
          @workflow_id = workflow_id
        end

        def execute
          # A new assessment is seeded with the incoming diff_sha purely so the row
          # satisfies its presence validation; the job owns writing the results.
          assessment = merge_request.risk_assessment || merge_request.build_risk_assessment(diff_sha: diff_sha)

          validation = validate(assessment)
          return validation if validation.error?

          refreshed = assessment.with_lock do
            result = assessment.refresh(diff_sha, sanitized_classification, workflow_id)
            # A scoring row refreshing again is a same-state loopback that saves nothing. The touch
            # stops the earlier submission's score job from failing the row when its retries run out.
            assessment.touch if result && assessment.previous_changes.empty?
            result
          end

          return refusal(assessment) unless refreshed

          ServiceResponse.success(payload: { assessment: assessment })
        end

        private

        attr_reader :merge_request, :classification, :diff_sha, :workflow_id

        def error(message)
          ServiceResponse.error(message: message)
        end

        def validate(assessment)
          return unknown_revision_error unless known_revision?
          return unknown_workflow_error unless session_for_this_merge_request?
          return stale_error(assessment) unless assessment.refreshable_for?(diff_sha)

          ServiceResponse.success
        end

        # Make sure a tampered workflow_id cannot be used to hijack another merge request's assessment.
        def session_for_this_merge_request?
          ::Ai::DuoWorkflows::Workflow
            .for_merge_request(merge_request)
            .with_workflow_definition(::Ai::Catalog::FoundationalFlow.risk_classification_v1.reference)
            .id_in(workflow_id)
            .exists?
        end

        # The event guard refuses an unknown revision on its own; this only exists
        # so the two rejections can be told apart in the response. A revision the
        # merge request has never seen usually means a caller bug, not a race.
        def known_revision?
          merge_request.merge_request_diffs.by_head_commit_sha(diff_sha).exists?
        end

        # The guard refused inside the lock: either a concurrent submission advanced
        # the assessment past this revision, or it sits in a state refresh can't leave.
        def refusal(assessment)
          validation = validate(assessment)
          return validation if validation.error?

          error(
            format(
              s_('RiskAssessment|Risk assessment cannot be refreshed while %{status}.'),
              status: assessment.status_name
            )
          )
        end

        # Deliberately says nothing about whether the session exists elsewhere.
        def unknown_workflow_error
          error(
            format(
              s_('RiskAssessment|workflow_id %{workflow_id} is not a risk assessment session ' \
                'for this merge request.'),
              workflow_id: workflow_id
            )
          )
        end

        def unknown_revision_error
          error(
            format(
              s_('RiskAssessment|diff_sha %{diff_sha} does not match any known revision of this merge request.'),
              diff_sha: diff_sha
            )
          )
        end

        def stale_error(assessment)
          error(
            format(
              s_("RiskAssessment|diff_sha %{diff_sha} is older than the assessment's " \
                'current diff_sha %{current_diff_sha}.'),
              diff_sha: diff_sha, current_diff_sha: assessment.diff_sha
            )
          )
        end

        # Only the two keys this service owns are persisted. Anything else the
        # caller sent is dropped rather than stored alongside the real one.
        def sanitized_classification
          {
            'claims' => classification['claims'].presence || {},
            'summary' => classification['summary'].presence
          }.compact
        end
      end
    end
  end
end
