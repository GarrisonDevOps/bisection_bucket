# frozen_string_literal: true

module Ai
  module Governance
    # Builds the downloadable JSON payload for an external agent session, in the same
    # shape as Ai::DuoWorkflows::SessionArtifactExportService.
    #
    # The session is a row hash from `siphon_ai_governance_sessions`, not an ActiveRecord model.
    class SessionArtifactExportService < ::Ai::DuoWorkflows::SessionArtifactExportService
      def initialize(session, current_user:)
        @session = session
        @current_user = current_user
      end

      private

      attr_reader :session, :current_user

      def session_summary
        {
          id: session['id'],
          source: ::Ai::Governance::Session.sources.key(session['source'].to_i),
          agent_type: session['agent_type'],
          flow_type: session['flow_type'],
          session_started_at: session_started_at&.iso8601,
          created_at: parse_time(session['created_at'])&.iso8601,
          updated_at: parse_time(session['updated_at'])&.iso8601,
          project: project_summary
        }
      end

      def project_summary
        project = ::Project.find_by_id(session['project_id']) if session['project_id']
        return unless project && Ability.allowed?(current_user, :read_project, project)

        {
          id: project.id,
          name: project.name,
          full_path: project.full_path
        }
      end

      def audit_event_rows(_workflow)
        query = ::AuditEvents::AiAuditEvents::ClickHouseFinder.new(
          ai_governance_session_id: session['id'],
          created_after: session_started_at && (session_started_at - ::Ai::Governance::Session::AUDIT_EVENTS_CLOCK_SKEW)
        ).execute

        ::ClickHouse::Client.select(query, :main)
      end

      def session_started_at
        parse_time(session['session_started_at'])
      end

      def parse_time(value)
        value.is_a?(String) ? Time.zone.parse(value) : value
      end
    end
  end
end
