# frozen_string_literal: true

module Ai
  module ExternalAgents
    module Sessions
      class CompleteService
        include ::Gitlab::InternalEventsTracking

        def initialize(project:, current_user:, session:, params:)
          @project = project
          @current_user = current_user
          @session = session
          @params = params
        end

        def execute
          result = complete
          ::Ai::ExternalAgents::AgentIdentity.record_sync(session.agent_identity_id) if result.success?
          result
        end

        private

        attr_reader :project, :current_user, :session, :params

        def complete
          return ServiceResponse.error(message: 'Unauthorized') unless authorized?
          return ServiceResponse.error(message: 'Session not found') unless session
          return ServiceResponse.error(message: 'Not session owner', reason: :forbidden) unless owner?
          return ServiceResponse.success(payload: { session: session }) if already_terminal?

          begin
            track_completion if complete_session
            ServiceResponse.success(payload: { session: session })
          rescue ActiveRecord::RecordInvalid => e
            ServiceResponse.error(message: e.message)
          end
        end

        def authorized?
          Ability.allowed?(current_user, :update_ai_agent_session, project)
        end

        def owner?
          session.user_id == current_user.id
        end

        def status_for_params
          params[:status] == 'completed' ? 'finished' : 'failed'
        end

        # Another request, such as an overlapping sync, can complete the session after it was loaded.
        # The lock re-reads it, so only one request completes and tracks it.
        def complete_session
          session.with_lock do
            next false if already_terminal?

            session.session_finished_at = Time.current
            session.status = status_for_params
            session.save!
          end
        end

        def track_completion
          track_internal_event(
            'complete_external_agent_session',
            user: current_user,
            project: project,
            additional_properties: { label: session.agent_type, property: session.status }
          )
        end

        def already_terminal?
          session.finished? || session.failed? || session.stopped?
        end
      end
    end
  end
end
