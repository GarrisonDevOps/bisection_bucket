# frozen_string_literal: true

# EE:Self Managed
module Admin
  module GitlabDuo
    class ConfigurationController < Admin::ApplicationController
      before_action :ensure_feature_available!

      respond_to :html

      feature_category :ai_abstraction_layer
      urgency :low

      before_action do
        push_frontend_feature_flag(:dap_instance_customizable_permissions, :instance, type: :wip)
        push_frontend_feature_flag(:duo_admin_access_rules_subgroups, :instance)
        push_frontend_feature_flag(:duo_auto_mode, :instance)
      end

      def index; end

      private

      def ensure_feature_available!
        redirect_to admin_gitlab_duo_path unless duo_configuration_available?
      end

      def duo_configuration_available?
        return false if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

        GitlabSubscriptions::Duo.active_self_managed_gitlab_credits? ||
          active_self_managed_duo_with_paid_license?
      end

      def active_self_managed_duo_with_paid_license?
        GitlabSubscriptions::Duo.active_self_managed_duo_core_pro_enterprise_or_self_hosted_dap? &&
          License.current&.paid?
      end
    end
  end
end
