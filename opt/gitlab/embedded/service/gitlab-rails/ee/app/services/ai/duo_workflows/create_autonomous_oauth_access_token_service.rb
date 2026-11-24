# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class CreateAutonomousOauthAccessTokenService
      include ::Services::ReturnServiceResponses
      include ::Gitlab::Utils::StrongMemoize

      TOKEN_EXPIRES_IN = 1.hour

      ALLOWED_SCOPES = ::Gitlab::Auth::AI_WORKFLOW_SCOPES.freeze

      def initialize(service_account:, organization:, container: nil, trigger_source: nil)
        @service_account = service_account
        @organization = organization
        @container = container
        @trigger_source = trigger_source
      end

      def execute
        unless @service_account&.service_account?
          return ServiceResponse.error(message: 'A valid service account is required for autonomous workflow execution')
        end

        unless @service_account.organization_id == @organization.id
          return ServiceResponse.error(message: 'Service account must belong to the same organization as the project')
        end

        unless ai_settings.duo_workflow_oauth_application.present?
          return ServiceResponse.error(
            message: 'OAuth application must be configured for autonomous workflow execution'
          )
        end

        token = create_oauth_access_token
        audit_token_creation(token)
        success(oauth_access_token: token)
      rescue ActiveRecord::RecordInvalid => e
        ServiceResponse.error(message: "Failed to generate autonomous oauth token: #{e.message}")
      end

      private

      def audit_token_creation(token)
        audit_context = {
          name: 'autonomous_oauth_token_created',
          author: @service_account,
          scope: @container || @service_account,
          target: @service_account,
          target_details: @service_account.name,
          message: 'Created autonomous OAuth token for Duo workflow',
          additional_details: {
            scopes: token.scopes.to_a,
            expires_in: TOKEN_EXPIRES_IN.to_i,
            trigger_source: @trigger_source.to_s
          }
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end

      def create_oauth_access_token
        return unless ai_settings.duo_workflow_oauth_application_id

        OauthAccessToken.create!(
          application_id: ai_settings.duo_workflow_oauth_application_id,
          expires_in: TOKEN_EXPIRES_IN,
          resource_owner_id: @service_account.id,
          organization: @organization,
          scopes: ALLOWED_SCOPES
        )
      end

      def ai_settings
        Ai::Setting.for_organization_read_only(@organization)
      end
      strong_memoize_attr :ai_settings
    end
  end
end
