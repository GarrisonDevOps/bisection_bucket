# frozen_string_literal: true

module Ai
  module RiskAssessment
    class CalculateScoreWorker
      include ApplicationWorker

      data_consistency :delayed
      idempotent!
      defer_on_database_health_signal :gitlab_main, [:merge_requests_risk_assessments]
      feature_category :dap_code_review
      urgency :low

      # The session hooks leave a scoring row to this job, so nothing else fails it
      # if the job never succeeds. Few retries keep that row from waiting for weeks.
      sidekiq_options retry: 3
      sidekiq_retries_exhausted do |job, _exception|
        assessment = MergeRequest.find_by_id(job['args'].first)&.risk_assessment
        next unless assessment

        job_created_at = Time.at(job['created_at']).utc

        ::Gitlab::Duo::RiskAssessment::MarkFailedService.new(
          assessment,
          # A queued row belongs to a newer session, and a row updated after this job was
          # created waits on a newer submission's job. Either one settles it.
          guard: ->(record) { record.scoring? && record.updated_at <= job_created_at },
          log_message: 'Risk classification scoring gave up after its retries'
        ).execute
      end

      def perform(merge_request_id, diff_sha, classification, workflow_id)
        merge_request = MergeRequest.find_by_id(merge_request_id)
        return unless merge_request

        assessment = merge_request.risk_assessment
        return unless assessment

        classification = (classification || {}).deep_stringify_keys
        result = score(merge_request, classification)

        # Locked so a concurrent session hook can't read a stale, still-scoring
        # in-memory status after this transaction commits and clobber the result.
        assessment.with_lock do
          unless assessment.accepts_score_for?(diff_sha)
            log_warning('Risk assessment score arrived for an assessment that is not waiting on this revision',
              assessment, diff_sha)
            next
          end

          assessment.update!(attributes_from(result, classification, diff_sha, workflow_id))
          assessment.finish
        end
      end

      private

      def log_warning(message, assessment, incoming_diff_sha)
        Gitlab::AppLogger.warn(
          message: message,
          merge_request_id: assessment.merge_request_id,
          status: assessment.status_name,
          incoming_diff_sha: incoming_diff_sha,
          assessment_diff_sha: assessment.diff_sha
        )
      end

      def score(merge_request, classification)
        signals = ::Gitlab::Duo::RiskAssessment::SignalsExtractor.new(merge_request).execute
        scoring_function = ::Gitlab::Duo::RiskAssessment::ScoringFunction.current

        scoring_function.new(
          claims: classification['claims'],
          signals: signals.signals,
          mitigations: signals.mitigations,
          missing: signals.missing
        ).execute
      end

      def attributes_from(result, classification, diff_sha, workflow_id)
        {
          diff_sha: diff_sha,
          duo_workflow_id: workflow_id,
          classification: classification,
          score: result.score,
          confidence: result.confidence,
          signal_breakdown: result.signal_breakdown,
          missing_signals: result.missing_signals,
          domain_tags: domain_tags_from(result),
          scoring_function_version: result.version,
          rationale: classification['summary'],
          assessed_at: Time.current
        }
      end

      def domain_tags_from(result)
        domain_names = ::Gitlab::Duo::RiskAssessment::Domain.all.map(&:name)

        result.signal_breakdown.filter_map do |contribution|
          signal = contribution['signal']
          signal if domain_names.include?(signal) && contribution['contribution'].to_f > 0
        end
      end
    end
  end
end
