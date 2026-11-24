# frozen_string_literal: true

module EE
  module Onboarding
    module Redirectable
      extend ::Gitlab::Utils::Override

      private

      def onboarding_first_step_path
        return unless ::Onboarding.enabled?

        if onboarding_status_presenter.redirect_to_customers_portal?
          users_sign_up_customers_portal_redirect_path
        else
          users_sign_up_welcome_path
        end
      end

      override :after_sign_up_path
      def after_sign_up_path
        if ::Onboarding.enabled?
          onboarding_first_step_path
        else
          super
        end
      end
    end
  end
end
