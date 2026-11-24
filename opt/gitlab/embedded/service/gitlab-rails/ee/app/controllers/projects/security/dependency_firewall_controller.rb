# frozen_string_literal: true

module Projects
  module Security
    class DependencyFirewallController < Projects::ApplicationController
      before_action :authorize_read_dependency_firewall_dashboard!

      feature_category :dependency_firewall
      urgency :low

      def show; end

      private

      def authorize_read_dependency_firewall_dashboard!
        return if ::Security::DependencyFirewall::Availability.enforced_for?(project) &&
          can?(current_user, :read_security_orchestration_policies, project)

        render_404
      end
    end
  end
end
