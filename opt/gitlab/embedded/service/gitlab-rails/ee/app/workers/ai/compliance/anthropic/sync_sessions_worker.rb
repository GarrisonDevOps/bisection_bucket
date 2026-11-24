# frozen_string_literal: true

module Ai
  module Compliance
    module Anthropic
      # Reads one page of an integration's Claude Code session list, records the sessions it
      # can attribute to a GitLab user, then enqueues itself for the next page. A broken walk
      # is not resumed: the next scheduled run lists the same trailing window again, which is
      # why retries are off.
      class SyncSessionsWorker
        include ApplicationWorker

        WINDOW = 12.hours
        PRODUCT_SURFACE = 'claude_code'
        CONCURRENCY_LIMIT = 10

        data_consistency :sticky
        feature_category :ai_governance
        # :throttled, not :low: concurrency_limit buffering counts toward :low's queueing target.
        urgency :throttled
        idempotent!
        worker_has_external_dependencies!
        concurrency_limit -> { CONCURRENCY_LIMIT }
        defer_on_database_health_signal :gitlab_main, [:ai_governance_sessions]
        sidekiq_options retry: 0

        # @param integration_id [Integer] id of the Ai::Compliance::Anthropic::Integration
        # @param page_token [String, nil] Anthropic list page token; nil starts a new walk
        # @param params [Hash] 'updated_at_gte' carries the walk's window start, so every
        #   page of one walk asks for the same window
        def perform(integration_id, page_token = nil, params = {})
          integration = ::Ai::Compliance::Anthropic::Integration.find_by_id(integration_id)
          return unless integration&.enabled?
          return unless Feature.enabled?(:claude_code_compliance_api_ingestion, integration.namespace)

          window_start = params['updated_at_gte'] || WINDOW.ago.utc.iso8601
          page = ::Ai::Compliance::Anthropic::Client.new(api_key: integration.api_key).local_sessions(
            updated_at_gte: window_start,
            limit: ::Ai::Compliance::Anthropic::Client::MAX_SESSIONS_LIMIT,
            page: page_token
          )

          ingest(integration, page.data)

          if page.next_page.blank?
            integration.update!(last_successful_sync_at: Time.current)
            log_extra_metadata_on_done(:walk_completed, true)
          else
            enqueue_next_page(integration_id, page_token, page.next_page, window_start)
          end
        end

        private

        def ingest(integration, sessions)
          resolver = ::Ai::Compliance::Anthropic::UserResolver.new(group: integration.namespace)
          counts = { sessions_recorded: 0, sessions_dropped: 0, sessions_skipped: 0, sessions_failed: 0 }

          sessions.each do |session_data|
            counts[ingest_session(integration, resolver, session_data)] += 1
          end

          log_hash_metadata_on_done({ sessions_listed: sessions.size, **counts })
        end

        def ingest_session(integration, resolver, session_data)
          return :sessions_skipped unless session_data['product_surface'] == PRODUCT_SURFACE

          user = resolver.resolve(session_data)
          return :sessions_dropped unless user

          result = Sessions::CreateService.new(integration, user: user, session_data: session_data).execute

          if result.error?
            log_failed_session(integration, session_data, result)
            return :sessions_failed
          end

          enqueue_transcript_sync(integration, result.payload[:session], session_data)
          :sessions_recorded
        end

        def enqueue_transcript_sync(integration, governance_session, session_data)
          walk_state = ::Ai::Compliance::Anthropic::Session.find_for(governance_session)
          return unless TranscriptTaper.due?(walk_state: walk_state, last_message_at: session_data['updated_at'])

          SyncTranscriptWorker.perform_async(integration.id, governance_session.id)
        end

        def log_failed_session(integration, session_data, result)
          ::Gitlab::AppJsonLogger.warn(
            build_structured_payload_labkit(
              ::Labkit::Fields::LOG_MESSAGE => 'Failed to record Anthropic session',
              :failure_reason => result.reason,
              ::Labkit::Fields::GL_NAMESPACE_ID => integration.namespace_id,
              :anthropic_session_id => session_data['id']
            )
          )
        end

        def enqueue_next_page(integration_id, page_token, next_page, window_start)
          if next_page == page_token
            raise ::Ai::Compliance::Anthropic::Client::RequestError,
              'Compliance API returned a page cursor that does not advance'
          end

          jid = self.class.perform_async(integration_id, next_page, { 'updated_at_gte' => window_start })
          log_extra_metadata_on_done(:next_page_jid, jid)
        end
      end
    end
  end
end
