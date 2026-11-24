# frozen_string_literal: true

module API
  module SecretsManagement
    # Non-CI/CD access to Secrets Manager. Mints a short-lived JWT that a client
    # presents to OpenBao directly to read secrets.
    class AccessTokens < ::API::Base
      feature_category :secrets_management

      before { authenticate! }

      helpers do
        def issue_access_token(secrets_manager)
          require_token_authentication!
          not_found! unless secrets_manager&.active_after_refresh?

          result = ::SecretsManagement::ApiAccess::IssueTokenService
            .new(secrets_manager, current_user, auth_via: secrets_manager_auth_via)
            .execute

          render_api_error!(result.message, :unprocessable_entity) if result.error?

          present result.payload[:token], with: ::API::Entities::SecretsManagement::AccessToken
        end

        # Minting is limited to token-based auth (PAT, service account, project
        # or group access token, OAuth). A browser session leaves no revocable
        # credential to rotate or expire during incident response, so it is
        # rejected here.
        def require_token_authentication!
          return if access_token

          forbidden!('This endpoint requires a personal, project, group, or service account access token')
        end

        def secrets_manager_auth_via
          # Service-account and resource-access tokens are themselves
          # PersonalAccessToken records, so the principal type must be resolved
          # before falling back to the token class.
          return 'service_account' if current_user.service_account?
          return 'resource_access_token' if current_user.project_bot?

          access_token.is_a?(::PersonalAccessToken) ? 'personal_access_token' : 'oauth'
        end
      end

      params do
        requires :id, types: [String, Integer], desc: 'The ID or URL-encoded path of the project'
      end
      resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
        segment ':id/secrets_manager' do
          desc 'Create a Secrets Manager access token for a project' do
            detail 'Mints a short-lived JWT for reading the project secrets directly from OpenBao. ' \
              'Introduced in GitLab 19.2.'
            hidden true
            success ::API::Entities::SecretsManagement::AccessToken
            failure [
              { code: 401, message: 'Unauthorized' },
              { code: 403, message: 'Forbidden' },
              { code: 404, message: 'Not found' },
              { code: 422, message: 'Unprocessable entity' }
            ]
            tags %w[secrets_manager]
          end
          route_setting :lifecycle, :beta
          route_setting :authorization,
            permissions: :create_secrets_manager_api_jwt, boundary_type: :project
          post 'access_token' do
            not_found! unless Feature.enabled?(:secrets_manager_api_access, user_project)

            authorize! :create_secrets_manager_api_jwt, user_project

            issue_access_token(user_project.secrets_manager)
          end
        end
      end

      params do
        requires :id, types: [String, Integer], desc: 'The ID or URL-encoded path of the group'
      end
      resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
        segment ':id/secrets_manager' do
          desc 'Create a Secrets Manager access token for a group' do
            detail 'Mints a short-lived JWT for reading the group secrets directly from OpenBao. ' \
              'Introduced in GitLab 19.2.'
            hidden true
            success ::API::Entities::SecretsManagement::AccessToken
            failure [
              { code: 401, message: 'Unauthorized' },
              { code: 403, message: 'Forbidden' },
              { code: 404, message: 'Not found' },
              { code: 422, message: 'Unprocessable entity' }
            ]
            tags %w[secrets_manager]
          end
          route_setting :lifecycle, :beta
          route_setting :authorization,
            permissions: :create_secrets_manager_api_jwt, boundary_type: :group
          post 'access_token' do
            not_found! unless Feature.enabled?(:secrets_manager_api_access, user_group)

            authorize! :create_secrets_manager_api_jwt, user_group

            issue_access_token(user_group.secrets_manager)
          end
        end
      end
    end
  end
end
