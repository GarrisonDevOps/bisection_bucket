# frozen_string_literal: true

module Admin
  module GitlabCreditsDashboard
    class CreditCapsController < Admin::ApplicationController
      feature_category :consumables_cost_management

      before_action :ensure_feature_available!
      before_action do
        push_frontend_feature_flag(:credit_caps_ui, :instance)
        push_frontend_feature_flag(:credit_caps_bulk_update, :instance)
      end

      private

      def ensure_feature_available!
        return render_404 unless Feature.enabled?(:credit_caps_ui, :instance)
        return render_404 if Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        render_404 unless License.gitlab_credits_entitled?
      end
    end
  end
end
