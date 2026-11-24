# frozen_string_literal: true

# EE:Self Managed
module Admin
  module GitlabDuo
    class SeatUtilizationController < Admin::ApplicationController
      include ::GitlabSubscriptions::CodeSuggestionsHelper

      respond_to :html

      feature_category :seat_cost_management
      urgency :low

      before_action :ensure_feature_available!
      before_action :ensure_seat_assignable_duo_add_on!

      def index
        @subscription_name = License.current.subscription_name
        @duo_add_on_start_date = duo_pro_or_enterprise_add_on_purchase&.started_at
        @duo_add_on_end_date = duo_pro_or_enterprise_add_on_purchase&.expires_on
      end

      private

      def ensure_feature_available!
        render_404 unless !gitlab_com_subscription? && License.current&.paid?
      end

      def ensure_seat_assignable_duo_add_on!
        redirect_to admin_gitlab_duo_path unless duo_pro_or_enterprise_add_on_purchase.present?
      end

      def duo_pro_or_enterprise_add_on_purchase
        @duo_pro_or_enterprise_add_on_purchase ||=
          GitlabSubscriptions::AddOnPurchase.for_self_managed.for_duo_pro_or_duo_enterprise.active.last
      end
    end
  end
end
