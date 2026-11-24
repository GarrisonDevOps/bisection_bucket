# frozen_string_literal: true

module Security
  module AgentArtifactsDownloadable
    extend ActiveSupport::Concern

    included do
      before_action :authorize_view_agent_artifacts!
      before_action -> { check_rate_limit!(:ai_session_artifact_download, scope: { user: current_user }) },
        only: [:download, :download_session],
        if: -> { ::Feature.enabled?(:ai_governance_rate_limits, ai_governance_sessions_namespace.root_ancestor) }
    end

    def download
      workflow = session_artifact(params.require(:id))
      return render_404 unless workflow

      send_session_artifact(workflow)
    end

    # Downloads an external agent session, keyed by the AI governance session ID.
    def download_session
      session = find_external_session(params.require(:id))
      return render_404 unless session

      send_json_artifact(
        ::Ai::Governance::SessionArtifactExportService.new(session, current_user: current_user), session['id']
      )
    end

    private

    # Including controllers must implement `find_session_artifact(id)` to return
    # the Ai::DuoWorkflows::Workflow backing the session, scoped to their
    # resource (group or project), or nil.
    #
    # Invoker-private sessions are filtered here, at retrieval, so any future
    # action using this lookup inherits the guard.
    def session_artifact(id)
      workflow = find_session_artifact(id)
      return if workflow&.private_messaging_session?

      workflow
    end

    def send_session_artifact(workflow)
      send_json_artifact(::Ai::DuoWorkflows::SessionArtifactExportService.new(workflow), workflow.id)
    end

    # Including controllers must implement `ai_governance_sessions_namespace` to return
    # the group, or the project namespace, that the session must belong to.
    # External sessions are read from ClickHouse only, like the AI governance sessions API.
    def find_external_session(id)
      namespace = ai_governance_sessions_namespace
      return unless ::Gitlab::ClickHouse.globally_enabled_for_analytics? &&
        Feature.enabled?(:ai_governance_sessions_api, namespace.root_ancestor)

      query = ::Ai::Governance::Sessions::ClickHouseFinder.new(
        current_user: current_user,
        namespace: namespace,
        params: { id: id.to_i, agent_class: :external }
      ).execute

      ::ClickHouse::Client.select(query.limit(1), :main).first
    end

    def send_json_artifact(export_service, id)
      send_data(
        ::Gitlab::Json.dump(export_service.as_json),
        type: 'application/json; charset=utf-8',
        filename: "session-artifact-#{id}.json",
        disposition: 'attachment'
      )
    end

    def authorize_view_agent_artifacts!
      raise NotImplementedError, "#{self.class} must implement #authorize_view_agent_artifacts!"
    end
  end
end
