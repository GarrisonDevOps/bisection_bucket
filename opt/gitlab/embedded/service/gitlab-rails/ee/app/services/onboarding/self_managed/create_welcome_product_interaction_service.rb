# frozen_string_literal: true

module Onboarding
  module SelfManaged
    class CreateWelcomeProductInteractionService
      PRODUCT_INTERACTION = 'SM Welcome Flow No Trial Contact'

      def initialize(user:)
        @user = user
      end

      def execute
        response = client.create_self_managed_welcome_contact({ lead: lead_params })

        if response[:success]
          ServiceResponse.success
        else
          error_message = response.dig(:data, :errors) || 'Submission failed'
          ServiceResponse.error(message: error_message, reason: :submission_failed)
        end
      end

      private

      attr_reader :user

      def client
        Gitlab::SubscriptionPortal::Client
      end

      def lead_params
        {
          first_name: user.first_name,
          last_name: user.last_name,
          email: email,
          company_name: user.user_detail.company,
          product_interaction: PRODUCT_INTERACTION,
          instance_id: Gitlab::GlobalAnonymousId.instance_id,
          country: user.user_detail.onboarding_status_country,
          hostname: Gitlab.config.gitlab.host,
          sign_up_date: Date.current.iso8601
        }.compact
      end

      # This email is sent immediately after registration during the Self-Managed profile step.
      # If the email address is updated during this step, it requires confirmation before
      # the change takes effect. We now send the opt-in email to the new address immediately
      # by checking for unconfirmed email addresses.
      def email
        user.unconfirmed_email || user.email
      end
    end
  end
end
