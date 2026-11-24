# frozen_string_literal: true

module AuditEvents
  module AiAuditEvents
    # Stores, streams, and logs a batch of unsaved AI audit events.
    class WriteService
      PG_FALLBACK_COUNTER = Gitlab::Metrics.counter(
        :gitlab_ai_audit_events_pg_fallback_total,
        'AI audit events stored via PostgreSQL fallback instead of ClickHouse'
      )

      # Counts events enqueued to the Redis write buffer (not yet persisted to CH).
      # The true CH-persisted count (via DumpWriteBufferWorker inserted_rows) is a
      # follow-up promotion out of scope here.
      BUFFERED_COUNTER = Gitlab::Metrics.counter(
        :gitlab_ai_audit_events_buffered_total,
        'AI audit events enqueued to the ClickHouse write buffer (Redis)'
      )

      STORED_COUNTER = Gitlab::Metrics.counter(
        :gitlab_ai_audit_events_stored_total,
        'AI audit events durably written to PostgreSQL'
      )

      # @param audit_events [Array<AuditEvents::AiAuditEvent>] unsaved events
      def initialize(audit_events)
        @audit_events = audit_events
      end

      def execute
        return if audit_events.blank?

        storable_events = audit_events.select { |event| store_event?(event) }

        store_audit_events(storable_events)
        stream_audit_events
        log_audit_events(storable_events)
      end

      private

      attr_reader :audit_events

      def store_audit_events(storable_events)
        return if storable_events.empty?

        if ::Gitlab::ClickHouse.globally_enabled_for_analytics?
          buffered = storable_events.count(&:store_to_clickhouse)
          BUFFERED_COUNTER.increment({}, buffered)
        else
          ::AuditEvents::AiAuditEvent.bulk_insert!(
            storable_events,
            skip_duplicates: true,
            unique_by: %i[cloud_event_id created_at]
          )

          PG_FALLBACK_COUNTER.increment({}, storable_events.size)
          # skip_duplicates: true means the unique index on (cloud_event_id, created_at)
          # silently ignores duplicates on retry - rows cannot be double-written; this
          # counts persistence attempts rather than guaranteed new rows.
          STORED_COUNTER.increment({ store: :postgresql }, storable_events.size)
        end
      end

      def store_event?(audit_event)
        storage_decisions[[audit_event.project_id, audit_event.namespace_id]]
      end

      # Events in a batch share a workflow, so this resolves at most once per scope.
      def storage_decisions
        @storage_decisions ||= Hash.new do |decisions, (project_id, namespace_id)|
          decisions[[project_id, namespace_id]] = storage_enabled?(project_id, namespace_id)
        end
      end

      def storage_enabled?(project_id, namespace_id)
        ::AuditEvents::AiAuditEvents::Settings.storage_enabled?(storage_resource(project_id, namespace_id))
      end

      def storage_resource(project_id, namespace_id)
        if project_id
          Project.find_by_id(project_id)
        elsif namespace_id
          Namespace.find_by_id(namespace_id)
        end
      end

      def stream_audit_events
        ::AuditEvents::AiAuditEvents::Streamer.stream(audit_events)
      end

      def log_audit_events(storable_events)
        logger = ::Gitlab::AuditJsonLogger.build

        storable_events.each do |audit_event|
          logger.info(
            event_name: audit_event.event_name,
            cloud_event_id: audit_event.cloud_event_id,
            author_id: audit_event.author_id,
            Labkit::Fields::REMOTE_IP => audit_event.ip_address.to_s,
            workflow_id: audit_event.workflow_id,
            project_id: audit_event.project_id,
            namespace_id: audit_event.namespace_id,
            details: audit_event.details,
            created_at: audit_event.created_at&.iso8601
          )
        end
      end
    end
  end
end
