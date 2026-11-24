# frozen_string_literal: true

module EE
  module DashboardHelper
    extend ::Gitlab::Utils::Override

    def controller_action_to_child_dashboards(controller = controller_name, action = action_name)
      case "#{controller}##{action}"
      when 'projects#index', 'root#index', 'projects#starred'
        %w[projects]
      when 'dashboard#activity'
        %w[starred_project_activity project_activity]
      when 'groups#index'
        %w[groups]
      when 'todos#index'
        %w[todos]
      when 'dashboard#issues'
        %w[issues]
      when 'dashboard#merge_requests'
        %w[merge_requests]
      else
        []
      end
    end

    def user_default_dashboard?(user)
      controller_action_to_child_dashboards.any?(user.dashboard)
    end

    # EE:Self Managed
    def has_start_trial?
      !current_user.has_current_license? && current_user.can_admin_all_resources?
    end

    override :user_groups_requiring_reauth
    def user_groups_requiring_reauth
      saml_providers = current_user.group_saml_identities.map(&:saml_provider)
      return super unless saml_providers.any?

      saml_providers.select! do |saml_provider|
        ::Gitlab::Auth::GroupSaml::SsoEnforcer.new(saml_provider, user: current_user).access_restricted?
      end

      saml_providers.map(&:group)
    end

    private

    def security_dashboard_available?
      security_dashboard = InstanceSecurityDashboard.new(current_user)

      security_dashboard.feature_available?(:security_dashboard) &&
        can?(current_user, :read_instance_security_dashboard, security_dashboard)
    end
  end
end
