# frozen_string_literal: true

module EE
  module Users
    module RegistrationsBuildService
      extend ::Gitlab::Utils::Override

      private

      override :signup_params
      def signup_params
        return super unless ::Onboarding.enabled?

        super + [:onboarding_status_email_opt_in]
      end
    end
  end
end
