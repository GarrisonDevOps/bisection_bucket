# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class OnboardingService
      include ::Services::ReturnServiceResponses
      include ::Gitlab::Utils::StrongMemoize

      ServiceAccountError = Class.new(StandardError)

      def initialize(current_user:, organization:)
        @current_user = current_user
        @organization = organization
      end

      def execute
        create_duo_workflow_service_account!
        create_composite_identity_oauth_application!

        if update_settings
          ServiceResponse.success(message: 'GitLab Duo Agent Platform onboarding for the instance is complete')
        else
          ServiceResponse.error(message: ai_settings.errors.full_messages.to_sentence)
        end
      end

      private

      def update_settings
        return false if ai_settings.errors.any?

        ai_settings.save
      end

      def create_duo_workflow_service_account!
        service_account_user = find_or_create_service_account!
        add_service_account_to_ai_settings(service_account_user)
      end

      def create_composite_identity_oauth_application!
        oauth_app = find_or_create_oauth_app!
        add_oauth_application_to_ai_settings(oauth_app)
      end

      def find_or_create_service_account!
        return duo_workflow_service_account if duo_workflow_service_account.present?

        service_account_result = ServiceResponse.from_legacy_hash(
          ::Users::ServiceAccounts::CreateService.new(
            @current_user, # instance admin
            {
              name: 'Duo Developer',
              username: 'duo-developer',
              composite_identity_enforced: true,
              organization_id: @organization.id,
              private_profile: true,
              skip_ai_prefix_validation: true
            }
          ).execute
        )

        if service_account_result.error?
          ai_settings.errors.add(:base, service_account_result.message)
          return
        end

        service_account_result.payload[:user]
      end

      def add_service_account_to_ai_settings(service_account_user)
        if service_account_user.nil? || service_account_user.id == ai_settings.duo_workflow_service_account_user_id
          return
        end

        ai_settings.duo_workflow_service_account_user_id = service_account_user.id
      end

      def find_or_create_oauth_app!
        return oauth_application if oauth_application

        Authn::OauthApplication.create!(
          name: 'GitLab Duo Agent Platform Composite OAuth Application',
          redirect_uri: oauth_callback_url,
          scopes: ::Gitlab::Auth::AI_WORKFLOW_SCOPES + [::Gitlab::Auth::MCP_SCOPE, ::Gitlab::Auth::DYNAMIC_USER],
          trusted: true,
          confidential: true,
          organization: @organization
        )
      end

      def add_oauth_application_to_ai_settings(oauth_app)
        return if oauth_app.nil? || oauth_app.id == ai_settings.duo_workflow_oauth_application_id

        ai_settings.duo_workflow_oauth_application_id = oauth_app.id
      end

      def duo_workflow_service_account
        ai_settings.duo_workflow_service_account_user
      end

      def oauth_application
        ai_settings.duo_workflow_oauth_application
      end

      def oauth_callback_url
        Gitlab::Routing.url_helpers.root_url
      end

      def ai_settings
        Ai::Setting.for_organization(@organization)
      end
      strong_memoize_attr :ai_settings
    end
  end
end
