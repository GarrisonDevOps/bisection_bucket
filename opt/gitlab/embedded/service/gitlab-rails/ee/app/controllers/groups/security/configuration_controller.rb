# frozen_string_literal: true

module Groups
  module Security
    class ConfigurationController < Groups::ApplicationController
      include ::Security::DismissesNavIndicator

      layout 'group'

      before_action :authorize_security_configuration!
      before_action -> { dismiss_security_nav_indicator(:configuration, group.root_ancestor) }, only: :show

      feature_category :security_testing_configuration

      def show
        push_frontend_feature_flag(:custom_scan_profiles_ui, group.root_ancestor)
        push_force_frontend_feature_flag(:bl_security_analyzer,
          ::Ai::Catalog::FoundationalFlow::BlSecurity::Definition.scan_profiles_enabled_for?(group.root_ancestor))
        push_frontend_feature_flag(:triage_and_remediation_profiles_ui, group.root_ancestor)
        push_frontend_feature_flag(:skillguard_analyzer, group.root_ancestor)
        push_frontend_feature_flag(:scanner_wizard_attach_modes, group.root_ancestor)
      end

      private

      def can_access_attributes?
        can?(current_user, :admin_security_attributes, group.root_ancestor) &&
          group.licensed_feature_available?(:security_attributes)
      end

      def can_access_scan_profiles?
        can?(current_user, :read_security_scan_profiles, group.root_ancestor) &&
          group.licensed_feature_available?(:security_scan_profiles)
      end

      def authorize_security_configuration!
        render_403 unless can_access_attributes? || can_access_scan_profiles?
      end
    end
  end
end
