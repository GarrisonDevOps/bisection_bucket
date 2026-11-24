# frozen_string_literal: true

module Groups
  module Settings
    class SecureController < Groups::ApplicationController
      layout 'group_settings'

      before_action :check_feature_availability
      before_action :authorize_admin_group!

      # The page gate allows Secrets Manager-only groups; update only touches the
      # dependency firewall, so it needs its own availability check.
      before_action :check_dependency_firewall_availability!, only: [:update]
      before_action :check_ai_governance_availability!, only: [:ai_governance]

      feature_category :dependency_firewall, [:show, :update]
      feature_category :ai_governance, [:ai_governance]
      urgency :low

      def show; end

      def update
        if Groups::UpdateService.new(group, current_user, dependency_firewall_params).execute
          flash[:notice] = s_('DependencyFirewall|Dependency firewall settings were successfully updated.')
        else
          flash[:alert] = s_('DependencyFirewall|Failed to update the dependency firewall settings.')
        end

        redirect_to group_settings_secure_path(group, anchor: 'js-dependency-firewall-settings')
      end

      def ai_governance
        if Groups::UpdateService.new(group, current_user, ai_governance_params).execute
          render json: {}, status: :ok
        else
          render json: { message: group.errors.full_messages.to_sentence }, status: :unprocessable_entity
        end
      end

      private

      def check_feature_availability
        render_404 unless group.secure_settings_available?
      end

      def check_dependency_firewall_availability!
        render_404 unless group.dependency_firewall_setting_available?
      end

      def check_ai_governance_availability!
        render_404 unless group.ai_governance_setting_available?
      end

      def dependency_firewall_params
        params.require(:group).permit(:dependency_firewall_enabled)
      end

      def ai_governance_params
        params.require(:group).permit(
          :ai_governance_enabled,
          :lock_ai_governance_enabled,
          :ai_audit_events_storage_enabled,
          :lock_ai_audit_events_storage_enabled
        )
      end
    end
  end
end
