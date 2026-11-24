# frozen_string_literal: true

module GitlabSubscriptions
  module UserAddOnAssignments
    module Saas
      class CreateService < ::GitlabSubscriptions::UserAddOnAssignments::Saas::CreateWithoutNotificationService
        extend ::Gitlab::Utils::Override

        private

        override :after_success_hook
        def after_success_hook
          super

          create_iterable_trigger if duo_pro? || duo_enterprise?
        end

        def create_iterable_trigger
          ::Onboarding::CreateIterableTriggerWorker.perform_async(iterable_params)
        end

        def iterable_params
          ::Onboarding.add_on_seat_assignment_iterable_params(
            user,
            ::GitlabSubscriptions::AddOns::VARIANTS[add_on_purchase.add_on_name.to_sym][:product_interaction],
            namespace
          )
        end
      end
    end
  end
end
