# frozen_string_literal: true

module EE
  module Admin
    module Registrations
      module ProfilesController
        extend ::Gitlab::Utils::Override

        override :new
        def new
          super

          return unless current_user.user_detail.onboarding_status_email_opt_in.nil?

          current_user.user_detail.onboarding_status_email_opt_in = true
        end

        override :update
        def update
          super

          submit_welcome_product_interaction
        end

        private

        def submit_welcome_product_interaction
          return unless eligible_for_welcome_product_interaction?

          ::Onboarding::SelfManaged::CreateWelcomeProductInteractionWorker.perform_async(current_user.id)
        end

        def eligible_for_welcome_product_interaction?
          response.redirect? &&
            current_user.user_detail.onboarding_status_email_opt_in &&
            !License.current&.trial?
        end

        override :verify_available!
        def verify_available!
          return render_404 if ::Gitlab::Saas.feature_available?(:subscriptions_trials)
          return render_404 if ::Gitlab::Dedicated.feature_available?(:skip_self_managed_onboarding)

          super
        end

        override :user_detail_params_attributes
        def user_detail_params_attributes
          super + [:onboarding_status_country, :onboarding_status_email_opt_in]
        end
      end
    end
  end
end
