# frozen_string_literal: true

module GitlabSubscriptions
  module UserAddOnAssignments
    module Saas
      class CreateWithoutNotificationService < ::GitlabSubscriptions::UserAddOnAssignments::BaseCreateService
        include Gitlab::Utils::StrongMemoize

        private

        def eligible_for_gitlab_duo_pro_seat?
          namespace.eligible_for_gitlab_duo_pro_seat?(user)
        end
        strong_memoize_attr :eligible_for_gitlab_duo_pro_seat?

        def namespace
          @namespace ||= add_on_purchase.namespace
        end

        def base_log_params
          super.merge(namespace: add_on_purchase.namespace.full_path)
        end
      end
    end
  end
end
