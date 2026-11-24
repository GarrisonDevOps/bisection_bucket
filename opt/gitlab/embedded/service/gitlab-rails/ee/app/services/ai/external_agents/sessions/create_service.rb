# frozen_string_literal: true

module Ai
  module ExternalAgents
    module Sessions
      class CreateService
        include ::Gitlab::InternalEventsTracking

        def initialize(project:, current_user:, params:)
          @project = project
          @current_user = current_user
          @params = params
        end

        def execute
          result = create_session
          ::Ai::ExternalAgents::AgentIdentity.record_sync(params[:agent_identity_id]) if result.success?
          result
        end

        private

        attr_reader :project, :current_user, :params

        def create_session
          return ServiceResponse.error(message: 'Unauthorized') unless authorized?
          return ServiceResponse.error(message: 'Agent identity not found', reason: :not_found) unless valid_identity?

          if params[:started_at].present? && params[:started_at].future?
            return ServiceResponse.error(message: 'started_at cannot be in the future')
          end

          if params[:started_at].present? && params[:started_at] < 30.days.ago
            return ServiceResponse.error(message: 'started_at cannot be more than 30 days in the past')
          end

          session = find_or_build_session
          return complete_session(session) if session.persisted?

          begin
            session.status = :running
            session.save!
            track_creation(session)

            ServiceResponse.success(payload: { session: session })
          rescue ActiveRecord::RecordNotUnique
            existing = existing_session
            if existing
              complete_session(existing)
            else
              ServiceResponse.error(message: 'Session already exists for this idempotency key')
            end
          rescue ActiveRecord::RecordInvalid => e
            ServiceResponse.error(message: e.message)
          end
        end

        # The token mint creates the session before audit sync registers it, so the first sync from the same identity
        # fills in what the mint could not know. A sync type on the row means a sync already registered it.
        # session_started_at keeps the mint's time: it is in the ClickHouse primary key, which must never change.
        def complete_session(session)
          if fill_from_sync?(session)
            session.with_lock do
              next unless session.sync_type.nil?

              session.update!(
                sync_type: params[:sync_type],
                flow_type: session.flow_type || params[:workflow_definition],
                glab_version: session.glab_version || params[:glab_version],
                agent_version: session.agent_version || params[:agent_version]
              )
            end
          end

          ServiceResponse.success(payload: { session: session })
        rescue ActiveRecord::RecordInvalid => e
          ServiceResponse.error(message: e.message)
        end

        def fill_from_sync?(session)
          session.sync_type.nil? && params[:sync_type].present? &&
            session.agent_identity_id == params[:agent_identity_id] && session.agent_type == params[:agent_type]
        end

        def authorized?
          Ability.allowed?(current_user, :create_ai_agent_session, project)
        end

        def find_or_build_session
          return existing_session if params[:idempotency_key].present? && existing_session

          ::Ai::Governance::Session.new(
            user: current_user,
            namespace: project.project_namespace,
            project: project,
            source: :claude_code_glab,
            external_xid: params[:idempotency_key] || SecureRandom.uuid,
            parent_external_xid: params[:parent_idempotency_key],
            agent_type: params[:agent_type],
            agent_identity_id: params[:agent_identity_id],
            flow_type: params[:workflow_definition],
            glab_version: params[:glab_version],
            agent_version: params[:agent_version],
            sync_type: params[:sync_type],
            session_started_at: params[:started_at] || Time.current,
            status: :created
          )
        end

        def track_creation(session)
          track_internal_event(
            'create_external_agent_session',
            user: current_user,
            project: project,
            additional_properties: { label: session.agent_type, property: params[:sync_type] }
          )
        end

        def existing_session
          return if params[:idempotency_key].blank?

          @existing_session ||= ::Ai::Governance::Session.find_by_external_xid(
            namespace_id: project.project_namespace_id,
            external_xid: params[:idempotency_key],
            user_id: current_user.id
          )
        end

        def valid_identity?
          return true unless params[:agent_identity_id].present?

          ::Ai::ExternalAgents::AgentIdentity.owned_by?(
            id: params[:agent_identity_id],
            user: current_user,
            project: project,
            agent_type: params[:agent_type]
          )
        end
      end
    end
  end
end
