# frozen_string_literal: true

module API
  module Ai
    class ThirdPartyAgents < ::API::Base
      include APIGuard

      feature_category :ai_catalog_curation
      urgency :low

      allow_access_with_scope [:ai_features, :api]

      helpers ::API::Helpers::AiUsersPerIpLimitHelpers

      helpers do
        def token_error_status(reason)
          case reason
          when :missing_duo_namespace then :unprocessable_entity
          when :duo_features_disabled then :forbidden
          when :insufficient_credits then :payment_required
          else :service_unavailable
          end
        end
      end

      before do
        authenticate!

        forbidden! unless Ability.allowed?(current_user, :create_third_party_agent_direct_access_token)
      end

      namespace :ai do
        namespace :third_party_agents do
          resources :direct_access do
            desc 'Get connection details for third party agents' do
              detail 'Returns connection details including tokens for accessing third-party agents.'
              success code: 201
              failure [
                { code: 401, message: 'Unauthorized' },
                { code: 402, message: 'Payment required' },
                { code: 403, message: 'Forbidden' },
                { code: 404, message: 'Not found' },
                { code: 422, message: 'Unprocessable entity' },
                { code: 429, message: 'Too many requests' },
                { code: 503, message: 'Service unavailable' }
              ]
              tags ['gitlab_duo']
            end

            route_setting :lifecycle, :experiment
            route_setting :authorization,
              permissions: :create_third_party_agent_direct_access_token,
              boundary_type: :user
            post do
              check_ai_users_per_ip_limit!

              token = ::Ai::ThirdPartyAgents::TokenService.new(
                current_user: current_user,
                organization: Current.organization
              ).direct_access_token

              render_api_error!(token.message, token_error_status(token.reason)) if token.error?

              present token.payload, with: Grape::Presenters::Presenter
            end
          end
        end
      end
    end
  end
end
