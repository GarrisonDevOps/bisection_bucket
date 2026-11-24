# frozen_string_literal: true

module Ai
  module ExternalAgents
    module Identities
      class RegisterService
        include ::Gitlab::InternalEventsTracking

        def initialize(project:, current_user:, params:)
          @project = project
          @current_user = current_user
          @params = params
        end

        def execute
          return ServiceResponse.error(message: 'Unauthorized', reason: :forbidden) unless authorized?

          identity = find_or_create_identity
          unless identity.persisted?
            return ServiceResponse.error(message: 'Failed to register identity',
              payload: { errors: identity.errors.full_messages })
          end

          if identity.revoked?
            return ServiceResponse.error(message: 'Agent identity has been revoked',
              reason: :forbidden)
          end

          track_registration(identity) if identity.previously_new_record?
          Ai::ExternalAgents::AgentIdentity.record_sync(identity.id)

          ServiceResponse.success(payload: { identity: identity })
        end

        private

        attr_reader :project, :current_user, :params

        def authorized?
          Ability.allowed?(current_user, :create_ai_agent_identity, project)
        end

        def track_registration(identity)
          track_internal_event(
            'register_external_agent_identity',
            user: current_user,
            project: project,
            additional_properties: { label: identity.agent_type }
          )
        end

        def find_or_create_identity
          Ai::ExternalAgents::AgentIdentity.register(
            user: current_user,
            project: project,
            agent_type: params[:agent_type],
            machine_fingerprint: params[:machine_fingerprint]
          )
        rescue ActiveRecord::RecordInvalid => e
          e.record
        end
      end
    end
  end
end
