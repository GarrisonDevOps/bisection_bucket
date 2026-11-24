# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # Builds the downloadable JSON payload for a Duo Agent Platform session
    # artifact: a session summary plus the session's audit events. Read-only;
    # follows the existing export-generator services (e.g. AuditEvents::ExportCsvService).
    class SessionArtifactExportService
      def initialize(workflow)
        @workflow = workflow
      end

      def as_json(*)
        {
          session: session_summary,
          audit_events: audit_events
        }
      end

      private

      attr_reader :workflow

      def session_summary
        {
          id: workflow.id,
          workflow_definition: workflow.workflow_definition,
          created_at: workflow.created_at&.iso8601,
          updated_at: workflow.updated_at&.iso8601,
          project: project_summary
        }
      end

      def project_summary
        project = workflow.project
        return unless project

        {
          id: project.id,
          name: project.name,
          full_path: project.full_path
        }
      end

      def audit_events
        audit_event_rows(workflow).map { |event| serialize_event(event) }
      end

      # The finder returns an ActiveRecord relation on the Postgres path and a
      # lazy ClickHouse::Client::QueryBuilder on the ClickHouse path; execute the
      # latter so callers always iterate over concrete rows.
      def audit_event_rows(workflow)
        result = ::AuditEvents::AiAuditEvents::Finder.new(workflow: workflow).execute
        return result unless result.is_a?(::ClickHouse::Client::QueryBuilder)

        ::ClickHouse::Client.select(result, :main)
      end

      def serialize_event(event)
        {
          id: fetch(event, :cloud_event_id) || fetch(event, :id),
          event_name: fetch(event, :event_name),
          author_id: fetch(event, :author_id),
          ip_address: fetch(event, :ip_address).to_s.presence,
          created_at: created_at_for(event),
          details: details_for(event)
        }
      end

      def created_at_for(event)
        value = fetch(event, :created_at)
        value = Time.zone.parse(value.to_s) unless value.is_a?(Time)
        value&.iso8601
      end

      def details_for(event)
        value = fetch(event, :details)
        return value if value.is_a?(Hash)
        return if value.blank?

        ::Gitlab::Json.safe_parse(value.to_s)
      rescue ::JSON::ParserError, ::EncodingError
        nil
      end

      # An audit event is an AuditEvents::AiAuditEvent record on the Postgres path
      # or a Hash row from ClickHouse; this hides that polymorphism.
      def fetch(event, key)
        if event.is_a?(Hash)
          event[key.to_s] || event[key]
        elsif event.respond_to?(key)
          event.read_attribute(key)
        end
      end
    end
  end
end
