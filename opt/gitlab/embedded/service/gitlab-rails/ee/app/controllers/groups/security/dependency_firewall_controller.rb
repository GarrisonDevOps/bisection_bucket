# frozen_string_literal: true

module Groups
  module Security
    class DependencyFirewallController < Groups::ApplicationController
      before_action :authorize_read_dependency_firewall_dashboard!

      feature_category :dependency_firewall
      urgency :low

      def show; end

      private

      def authorize_read_dependency_firewall_dashboard!
        return if ::Security::DependencyFirewall::Availability.enforced_for?(group) &&
          can?(current_user, :read_security_orchestration_policies, group)

        render_404
      end
    end
  end
end
