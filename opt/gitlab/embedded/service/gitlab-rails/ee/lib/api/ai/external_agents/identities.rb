# frozen_string_literal: true

module API
  module Ai
    module ExternalAgents
      class Identities < ::API::Base
        feature_category :software_composition_analysis

        before do
          authenticate!
        end

        resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
          before do
            user_project = find_project!(params[:id])
            not_found! unless Feature.enabled?(:ai_agent_session_tracking, user_project)

            forbidden! unless user_project.licensed_feature_available?(:ai_catalog)

            if ::Ai::Governance::AgentGovernance.report_disabled_to?(current_user, user_project)
              not_found!('AI agent governance')
            end
          end

          namespace ':id/ai_agent/identities' do
            desc 'Register an external agent identity.' do
              detail 'Registers a new agent identity for the current user, project, agent type, ' \
                'and machine fingerprint combination. Returns an existing record if one already ' \
                'exists. Returns 403 if the identity has been revoked.'
              success ::API::Entities::Ai::ExternalAgents::Identity
              failure [
                { code: 400, message: 'Bad request' },
                { code: 401, message: 'Unauthorized' },
                { code: 403, message: 'Forbidden' },
                { code: 404, message: 'Not found' }
              ]
              tags %w[projects ai_agent_identities]
            end
            params do
              requires :agent_type, type: String,
                desc: 'Type of agent being registered.',
                values: ::Ai::ExternalAgents::AgentIdentity::AGENT_TYPES
              requires :machine_fingerprint, type: String,
                desc: 'SHA-256 hash of the machine identifier.',
                limit: 64,
                allow_blank: false
            end
            route_setting :lifecycle, :experiment
            route_setting :tier, :premium
            route_setting :authorization, permissions: :create_ai_agent_identity, boundary_type: :project
            post do
              authorize! :create_ai_agent_identity, user_project
              check_rate_limit!(:ai_agent_identity_registration, scope: { user: current_user, project: user_project })

              result = ::Ai::ExternalAgents::Identities::RegisterService.new(
                project: user_project,
                current_user: current_user,
                params: declared_params(include_missing: false)
              ).execute

              if result.success?
                status :created
                present result.payload[:identity],
                  with: ::API::Entities::Ai::ExternalAgents::Identity
              elsif result.reason == :forbidden
                forbidden!(result.message)
              else
                bad_request!(result.message)
              end
            end
          end
        end
      end
    end
  end
end
