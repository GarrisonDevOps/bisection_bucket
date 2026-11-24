# frozen_string_literal: true

module Ai
  module Compliance
    module Anthropic
      module Transcripts
        # Reads one page of one Claude Code transcript, newest message first, and writes its audit
        # events. The newest message id, read from the first page with messages, rides along as
        # `candidate_watermark` and is committed only by the page that reaches a stop, after its
        # writes succeed. A failed page commits nothing, so a retry or the next walk reads those
        # messages again.
        #
        # The payload's `action` tells the caller what to do next: `:stop`, `:continue` with
        # `next_params`, or `:reschedule` with `next_params`. `metadata` is for the job log.
        class SyncPageService
          include ::Gitlab::Loggable

          MESSAGES_PER_PAGE = 500
          EVENTS_PER_WRITE = 100

          # A tuning value, not measured. Above the limit, Duo's events keep the shared buffer.
          WRITE_BUFFER_PENDING_LIMIT = 100_000

          # @param params [Hash] 'page_token' (nil starts a new walk), 'candidate_watermark' and
          #   'walk_started_at' (ISO 8601) carried from the walk's earlier pages
          def initialize(integration, governance_session, params = {})
            @integration = integration
            @governance_session = governance_session
            @page_token = params['page_token']
            @candidate_watermark = params['candidate_watermark']
            @walk_started_at = params['walk_started_at']
            @metadata = {}
          end

          def execute
            session_xid = governance_session.external_xid
            return response(:stop) if session_xid.blank?

            @walk_state = Session.find_or_create_for!(
              anthropic_integration: integration,
              ai_governance_session: governance_session,
              session_xid: session_xid
            )

            read_page(session_xid)
          rescue Client::SessionNotFoundError
            # The session aged out at Anthropic; nothing is left to read.
            walk_state.commit_walk!(nil, walk_started_at: walk_started_at)
            metadata[:session_not_found] = true
            response(:stop)
          end

          private

          attr_reader :integration, :governance_session, :walk_state, :page_token, :candidate_watermark,
            :walk_started_at, :metadata

          def read_page(session_xid)
            page = fetch_page(session_xid)

            # A restart after an expired cursor is a new first page.
            if page_token.nil?
              walk_state.start_walk!
              @walk_started_at = walk_state.walk_started_at.iso8601(6)
              @candidate_watermark = page.data.first&.dig('id')
              log_session_length(page)
            end

            # A first page can be empty and still point to a next page.
            @candidate_watermark ||= page.data.first&.dig('id')

            messages, reached_watermark = unread_messages(page.data)
            audit_events = build_audit_events(page.session, messages)

            if audit_events.any? && write_buffer_full?
              metadata[:write_buffer_rescheduled] = true
              return response(:reschedule, next_params(page_token))
            end

            write_audit_events(audit_events)
            metadata.merge!(messages_read: page.data.size, messages_ingested: messages.size)

            return commit_walk if reached_watermark || page.next_page.blank?

            if page.next_page == page_token
              raise Client::RequestError, 'Compliance API returned a page cursor that does not advance'
            end

            response(:continue, next_params(page.next_page))
          end

          # Message cursors expire 24 hours after a walk's first page, so start the walk again from
          # the newest page. Safe because the stored watermark has not moved.
          def fetch_page(session_xid)
            request_page(session_xid, page_token)
          rescue Client::PageCursorExpiredError
            raise if page_token.nil?

            metadata[:walk_restarted] = true
            @page_token = nil
            request_page(session_xid, nil)
          end

          def request_page(session_xid, token)
            client.local_session_messages(session_xid, order: 'desc', limit: MESSAGES_PER_PAGE, page: token)
          end

          def client
            @client ||= Client.new(api_key: integration.api_key)
          end

          # Everything before the stored watermark is new; the watermark and anything after it
          # were ingested by an earlier walk.
          def unread_messages(messages)
            watermark = walk_state.message_watermark
            stop_at = watermark.present? ? messages.index { |message| message['id'] == watermark } : nil

            stop_at ? [messages.first(stop_at), true] : [messages, false]
          end

          def build_audit_events(session_envelope, messages)
            return [] if messages.empty?

            transformer = TransformService.new(anthropic_user_id: session_envelope&.dig('user', 'id'))

            messages.flat_map { |message| transform(transformer, message) }.map do |event|
              ::AuditEvents::AiAuditEvent.new(event.merge(
                author_id: governance_session.user_id,
                namespace_id: integration.namespace_id,
                ai_governance_session_id: governance_session.id
              ))
            end
          end

          # A message that can never be stored is skipped, so it cannot fail the page on every walk.
          def transform(transformer, message)
            transformer.execute(message)
          rescue TransformService::InvalidMessageError => e
            ::Gitlab::AppJsonLogger.warn(
              build_structured_payload_labkit(
                ::Labkit::Fields::LOG_MESSAGE => 'Skipped Claude Code transcript message',
                :skip_reason => e.message,
                :anthropic_message_id => message['id'],
                :ai_governance_session_id => governance_session.id
              )
            )

            []
          end

          # Only the ClickHouse path uses the buffer; without ClickHouse a leftover backlog must not
          # stall ingestion.
          def write_buffer_full?
            return false unless ::Gitlab::ClickHouse.globally_enabled_for_analytics?

            ::ClickHouse::WriteBuffer.pending(::AuditEvents::AiAuditEvent::CLICKHOUSE_TABLE_NAME) >
              WRITE_BUFFER_PENDING_LIMIT
          end

          def write_audit_events(audit_events)
            audit_events.each_slice(EVENTS_PER_WRITE) do |chunk|
              ::AuditEvents::AiAuditEvents::WriteService.new(chunk).execute
            end

            metadata[:audit_events_written] = audit_events.size
          end

          # A no-op when a newer walk has started since; that walk's commit wins.
          def commit_walk
            if walk_state.commit_walk!(candidate_watermark, walk_started_at: walk_started_at)
              metadata[:walk_completed] = true
            else
              metadata[:stale_walk_skipped] = true
            end

            response(:stop)
          end

          # Validates the trailing window constant
          # (https://gitlab.com/gitlab-org/gitlab/-/work_items/623180).
          def log_session_length(page)
            last_message_at = parse_time(page.data.first&.dig('created_at'))
            session_created_at = parse_time(page.session&.dig('created_at')) || governance_session.session_started_at
            return unless last_message_at && session_created_at

            metadata[:session_length_seconds] = (last_message_at - session_created_at).round
          end

          def parse_time(value)
            return if value.blank?

            value.is_a?(String) ? Time.iso8601(value) : value
          rescue ArgumentError
            nil
          end

          def next_params(token)
            {
              'page_token' => token,
              'candidate_watermark' => candidate_watermark,
              'walk_started_at' => walk_started_at
            }.compact
          end

          def response(action, next_params = nil)
            ServiceResponse.success(payload: { action: action, next_params: next_params, metadata: metadata })
          end
        end
      end
    end
  end
end
