# frozen_string_literal: true

module API
  module Internal
    class Observability < ::API::Base
      include APIGuard

      before do
        verify_workhorse_api!
        content_type Gitlab::Workhorse::INTERNAL_API_CONTENT_TYPE
        authenticate!
      end

      helpers do
        include ::Gitlab::Utils::StrongMemoize

        def project
          @project ||= find_project(params[:id])
        end

        def cc_access_token
          root_group_id = project.root_ancestor.id
          CloudConnector::Tokens.get(
            resource: project,
            extra_claims: { gitlab_namespace_id: root_group_id.to_s },
            unit_primitive: :observability_all
          )
        end
        strong_memoize_attr :cc_access_token

        def respond_success
          status 200
          {
            'gob' => {
              'backend' => observability_url,
              'headers' => ::CloudConnector.headers(current_user).merge({
                'X-GitLab-Namespace-id' => project.root_ancestor.id.to_s,
                'X-GitLab-Project-id' => project.id.to_s,
                'Authorization' => "Bearer #{cc_access_token}",
                'X-Request-ID' => Labkit::Correlation::CorrelationId.current_or_new_id
              })
            }
          }
        end

        def observability_url
          request.post? ? Gitlab::Observability.observability_ingest_url : ::Gitlab::Observability.observability_url
        end

        def can_read
          Ability.allowed?(current_user, :read_observability, project)
        end

        def can_write
          Ability.allowed?(current_user, :write_observability, project)
        end
      end

      namespace 'internal' do
        namespace 'observability/project' do
          params do
            requires :id, types: [String, Integer],
              desc: 'The ID or URL-encoded path of the project'
          end

          namespace ':id/read' do
            route_setting :authorization, skip_granular_token_authorization: :workhorse_verification_auth
            get '/analytics', feature_category: :observability, urgency: :high do
              not_found! unless can_read
              respond_success
            end
            route_setting :authorization, skip_granular_token_authorization: :workhorse_verification_auth
            get '/traces', feature_category: :observability, urgency: :high do
              not_found! unless can_read
              respond_success
            end
            route_setting :authorization, skip_granular_token_authorization: :workhorse_verification_auth
            get '/services', feature_category: :observability, urgency: :high do
              not_found! unless can_read
              respond_success
            end
            route_setting :authorization, skip_granular_token_authorization: :workhorse_verification_auth
            get '/metrics', feature_category: :observability, urgency: :high do
              not_found! unless can_read
              respond_success
            end
            route_setting :authorization, skip_granular_token_authorization: :workhorse_verification_auth
            get '/logs', feature_category: :observability, urgency: :high do
              not_found! unless can_read
              respond_success
            end
          end

          namespace ':id/write' do
            route_setting :authorization, skip_granular_token_authorization: :workhorse_verification_auth
            post '/traces', feature_category: :observability, urgency: :high do
              not_found! unless can_write
              respond_success
            end
            route_setting :authorization, skip_granular_token_authorization: :workhorse_verification_auth
            post '/metrics', feature_category: :observability, urgency: :high do
              not_found! unless can_write
              respond_success
            end
            route_setting :authorization, skip_granular_token_authorization: :workhorse_verification_auth
            post '/logs', feature_category: :observability, urgency: :high do
              not_found! unless can_write
              respond_success
            end
          end
        end
      end
    end
  end
end

API::Internal::Observability.prepend_mod_with('API::Internal::Observability')
