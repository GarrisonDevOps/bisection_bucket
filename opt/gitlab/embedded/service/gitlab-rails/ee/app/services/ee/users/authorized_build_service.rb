# frozen_string_literal: true

module EE
  module Users
    module AuthorizedBuildService
      extend ::Gitlab::Utils::Override

      PROVIDERS_ALLOWED_TO_SKIP_CONFIRMATION = [::Users::BuildService::GROUP_SCIM_PROVIDER,
        ::Users::BuildService::GROUP_SAML_PROVIDER].freeze

      override :initialize
      def initialize(current_user, params = nil)
        super

        set_skip_confirmation_param
      end

      private

      override :signup_params
      def signup_params
        return super unless ::Onboarding.enabled?

        # TrialRegistrationsController and OmniAuthCallbacksController both pass an onboarding_status_email_opt_in
        # param so we need to be sure to allow it here.
        super + [:onboarding_status_email_opt_in]
      end

      def group
        return unless params[:group_id]

        strong_memoize(:group) do
          ::Group.find(params[:group_id])
        end
      end

      def set_skip_confirmation_param
        return if params[:skip_confirmation] # Explicit skip confirmation passed as param
        return unless provider_or_service_account_allowed_to_skip_confirmation?

        params[:skip_confirmation] = true if group&.root_ancestor&.owner_of_email?(params[:email])
      end

      def provider_or_service_account_allowed_to_skip_confirmation?
        PROVIDERS_ALLOWED_TO_SKIP_CONFIRMATION.include?(params[:provider]) ||
          params[:user_type] == :service_account
      end
    end
  end
end
