# frozen_string_literal: true

module Ai
  module AmazonQ
    class CreateService < BaseService
      DEFAULT_USERNAME = 'amazon-q'

      def execute
        return ServiceResponse.error(message: 'Missing organization_id parameter') \
          unless params[:organization_id].present?

        return ServiceResponse.error(message: 'Missing role_arn parameter') unless params[:role_arn].present?
        return availability_param_error if availability_param_error

        if update_settings
          create_audit_event(audit_availability: true, audit_ai_settings: true)
          ServiceResponse.success
        else
          ServiceResponse.error(message: ai_settings.errors.full_messages.to_sentence)
        end
      end

      private

      attr_accessor :user, :params

      def update_settings
        return unless ai_settings.update(amazon_q_role_arn: params[:role_arn])

        return unless ApplicationSettings::UpdateService.new(
          application_settings,
          user,
          { duo_availability: params[:availability] }
        ).execute

        return unless create_amazon_q_onboarding

        update_integration(params)
      end

      def create_amazon_q_onboarding
        service_account = existing_q_service_account || create_service_account
        return unless service_account

        ensure_service_account_block_status(service_account: service_account)

        return unless find_or_create_oauth_app
        return unless ai_settings.update(amazon_q_oauth_application_id: @application.id)
        return unless register_oauth_application_with_amazon

        ai_settings.update(amazon_q_ready: true)
      end

      def create_service_account
        service_account_result = ServiceResponse.from_legacy_hash(
          ::Users::ServiceAccounts::CreateService.new(
            @user,
            {
              name: 'Amazon Q Service',
              username: username,
              avatar: Users::Internal.bot_avatar(image: 'q_avatar.png'),
              composite_identity_enforced: true,
              organization_id: params[:organization_id],
              private_profile: true
            }
          ).execute
        )

        if service_account_result.error?
          ai_settings.errors.add(:amazon_q_service_account, service_account_result.message)
          return
        end

        service_account = service_account_result.payload[:user]
        return unless ai_settings.update(amazon_q_service_account_user_id: service_account.id)

        service_account
      end

      def ensure_service_account_block_status(service_account: nil)
        if Ai::AmazonQ.should_block_service_account?(availability: params[:availability])
          Ai::AmazonQ.ensure_service_account_blocked!(current_user: user, service_account: service_account)
        else
          Ai::AmazonQ.ensure_service_account_unblocked!(current_user: user, service_account: service_account)
        end
      end

      def existing_q_service_account
        ai_settings.amazon_q_service_account_user
      end

      def username
        format_username = ->(counter) do
          if counter.to_i > 0
            "#{DEFAULT_USERNAME}-#{counter}"
          else
            DEFAULT_USERNAME
          end
        end

        Gitlab::Utils::Uniquify.new.string(format_username) do |candidate|
          username_exists?(candidate)
        end
      end

      def username_exists?(username)
        User.find_by_username(username).present?
      end

      def find_or_create_oauth_app
        @application = existing_q_oauth_application
        return true if @application

        @application = Authn::OauthApplication.new(
          name: 'Amazon Q OAuth',
          redirect_uri: oauth_callback_url,
          scopes: ::Gitlab::Auth::Q_SCOPES + [::Gitlab::Auth::DYNAMIC_USER],
          trusted: false,
          confidential: false,
          organization_id: params[:organization_id]
        )
        @application.save
      end

      def register_oauth_application_with_amazon
        client = ::Gitlab::Llm::QAi::Client.new(user)
        # Currently the AI Gateway API call is idempotent; it will remove the existing
        # application if it already exists.
        response = client.perform_create_auth_application(
          @application,
          @application.secret,
          params[:role_arn]
        )
        return true if response.success?

        ai_settings.errors.add(:application,
          "could not be created by the AI Gateway: Error #{response.code} - #{response.body}")
        false
      end

      def existing_q_oauth_application
        oauth_app_id && oauth_application
      end

      def oauth_application
        Authn::OauthApplication.find_by_id(oauth_app_id)
      end

      def oauth_callback_url
        # This value is unused but cannot be nil
        Gitlab::Routing.url_helpers.root_url
      end

      def oauth_app_id
        ai_settings.amazon_q_oauth_application_id
      end
    end
  end
end
