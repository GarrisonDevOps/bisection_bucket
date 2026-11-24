# frozen_string_literal: true

module GitlabSubscriptions
  module UserAddOnAssignments
    module SelfManaged
      class CreateService < ::GitlabSubscriptions::UserAddOnAssignments::BaseCreateService
        include Gitlab::Utils::StrongMemoize
        extend ::Gitlab::Utils::Override

        private

        override :after_success_hook
        def after_success_hook
          super

          send_duo_seat_assignment_email if Feature.enabled?(:sm_duo_seat_assignment_email, :instance)
        end

        def eligible_for_gitlab_duo_pro_seat?
          ::Ai::UserAuthorizer.for(user).eligible_for_self_managed_gitlab_duo_pro?
        end
        strong_memoize_attr :eligible_for_gitlab_duo_pro_seat?

        def send_duo_seat_assignment_email
          DuoSeatAssignmentMailer.duo_pro_email(user).deliver_later if add_on_purchase.add_on.code_suggestions?
          DuoSeatAssignmentMailer.duo_enterprise_email(user).deliver_later if add_on_purchase.add_on.duo_enterprise?
        end
      end
    end
  end
end
