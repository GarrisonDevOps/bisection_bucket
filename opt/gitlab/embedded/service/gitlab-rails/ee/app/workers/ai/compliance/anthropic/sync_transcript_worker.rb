# frozen_string_literal: true

module Ai
  module Compliance
    module Anthropic
      # Walks one Claude Code transcript a page per job. Transcripts::SyncPageService reads and
      # writes the page; this worker enqueues the next page or reschedules a page the write buffer
      # cannot take yet.
      class SyncTranscriptWorker
        include ApplicationWorker

        CONCURRENCY_LIMIT = 10
        WRITE_BUFFER_RESCHEDULE_DELAY = 5.minutes

        # A buffer that stays full for longer than the 12-hour list window loses messages.
        WRITE_BUFFER_RESCHEDULES_COUNTER = ::Gitlab::Metrics.counter(
          :gitlab_ai_compliance_anthropic_transcript_buffer_reschedules_total,
          'Claude Code transcript pages rescheduled because the AI audit events write buffer was full'
        )

        data_consistency :sticky
        feature_category :ai_governance
        # :throttled, not :low: concurrency_limit buffering counts toward :low's queueing target.
        urgency :throttled
        idempotent!
        worker_has_external_dependencies!
        concurrency_limit -> { CONCURRENCY_LIMIT }
        defer_on_database_health_signal :gitlab_main, [:ai_audit_events, :ai_compliance_anthropic_sessions]
        sidekiq_options retry: 3

        # Log-only: the walk's walk_started_at stays set, and the next walk starts over from the
        # stored watermark. Page tokens are not logged.
        sidekiq_retries_exhausted do |job, exception|
          ::Gitlab::AppJsonLogger.error(
            ::Labkit::Fields::CLASS_NAME => name,
            ::Labkit::Fields::LOG_MESSAGE => 'Claude Code transcript walk failed: retries exhausted',
            ::Labkit::Fields::ERROR_TYPE => exception.class.name,
            ::Labkit::Fields::ERROR_MESSAGE => exception.message,
            :ai_governance_session_id => job['args'].second
          )
        end

        # @param integration_id [Integer] id of the Ai::Compliance::Anthropic::Integration
        # @param ai_governance_session_id [Integer] id of the Ai::Governance::Session the events are stamped with
        # @param params [Hash] walk state carried between pages; see Transcripts::SyncPageService
        def perform(integration_id, ai_governance_session_id, params = {})
          integration = Integration.find_by_id(integration_id)
          return unless integration&.enabled?
          return unless Feature.enabled?(:claude_code_compliance_api_ingestion, integration.namespace)

          governance_session = ::Ai::Governance::Session.find_by_id(ai_governance_session_id)
          return unless governance_session && governance_session.namespace_id == integration.namespace_id

          result = Transcripts::SyncPageService.new(integration, governance_session, params).execute
          log_hash_metadata_on_done(result.payload[:metadata])

          case result.payload[:action]
          when :continue
            self.class.perform_async(integration_id, ai_governance_session_id, result.payload[:next_params])
          when :reschedule
            WRITE_BUFFER_RESCHEDULES_COUNTER.increment
            self.class.perform_in(
              WRITE_BUFFER_RESCHEDULE_DELAY, integration_id, ai_governance_session_id, result.payload[:next_params]
            )
          end
        end
      end
    end
  end
end
