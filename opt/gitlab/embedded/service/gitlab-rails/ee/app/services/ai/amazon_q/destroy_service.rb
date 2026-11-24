# frozen_string_literal: true

module Ai
  module AmazonQ
    class DestroyService < BaseService
      def execute
        unless destroy_oauth_application!
          return ServiceResponse.error(message: ai_settings.errors.full_messages.to_sentence)
        end

        result = block_service_account!

        return result unless result.success?

        return ServiceResponse.error(message: ai_settings.errors.full_messages.to_sentence) unless destroy_integration

        if ai_settings.update(
          amazon_q_oauth_application_id: nil,
          amazon_q_ready: false,
          amazon_q_role_arn: nil
        )
          create_audit_event(
            audit_availability: false,
            audit_ai_settings: true,
            exclude_columns: %w[amazon_q_service_account_user_id]
          )

          ServiceResponse.success
        else
          ServiceResponse.error(message: ai_settings.errors.full_messages.to_sentence)
        end
      end

      private

      attr_reader :user

      def destroy_oauth_application!
        return unless delete_amazon_q_onboarding.success?

        oauth_application = Authn::OauthApplication.find_by_id(ai_settings.amazon_q_oauth_application_id)
        oauth_application&.destroy!

        true
      end

      def block_service_account!
        Ai::AmazonQ.ensure_service_account_blocked!(current_user: user)
      end

      def delete_amazon_q_onboarding
        client = ::Gitlab::Llm::QAi::Client.new(user)
        # Currently the AI Gateway API call is idempotent; it will remove the existing
        # application if it already exists.
        response = client.perform_delete_auth_application(
          ai_settings.amazon_q_role_arn
        )

        unless response.success?
          if response.code == 401 && response.body&.include?("Header mismatch 'X-Gitlab-Instance-Id'")
            ai_settings.errors.add(:uuid_mismatch, UUID_MISMATCH_ERROR_MESSAGE)
          else
            ai_settings.errors.add(:application,
              "could not be deleted by the AI Gateway: Error #{response.code} - #{response.body}")
          end
        end

        response
      end

      def destroy_integration
        integration = Integrations::AmazonQ.for_organization(ai_settings.organization_id).first
        return true unless integration

        unless integration.destroy
          ai_settings.errors.add(:base,
            "Failed to delete an integration: Error #{integration.errors.full_messages.to_sentence}")
        end

        integration.destroyed?
      end
    end
  end
end
