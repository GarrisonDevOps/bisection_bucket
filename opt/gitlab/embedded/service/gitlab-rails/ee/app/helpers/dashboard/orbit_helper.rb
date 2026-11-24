# frozen_string_literal: true

module Dashboard
  module OrbitHelper
    include ::Analytics::Orbit::PlatformHelper

    def orbit_app_data
      duo_accessible = duo_accessible?
      admin_configure_available = admin_orbit_configure_available?
      trial_available = orbit_trial_available?
      saas = ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
      queries_available = saas || ::Analytics::KnowledgeGraph.accessible_for?(current_user)

      data = {
        router_base: dashboard_orbit_path,
        duo_accessible: duo_accessible.to_s,
        can_ask_duo_for_queries: duo_accessible.to_s,
        orbit_settings_enabled: orbit_settings_enabled?.to_s,
        orbit_platform: orbit_platform(instance: !queries_available),
        queries_available: queries_available.to_s,
        trial_available: trial_available.to_s,
        default_group_missing: orbit_default_group_missing?.to_s,
        list_all_groups: admin_configure_available.to_s,
        preferences_path: profile_preferences_path(anchor: 'orbit-default-group')
      }

      data[:admin_configuration_path] = admin_orbit_path if admin_configure_available
      data.merge!(orbit_hand_raise_lead_data) if trial_available

      data
    end

    private

    def orbit_hand_raise_lead_data
      hand_raise = hand_raise_modal_dataset(current_user.namespace)

      { hand_raise_lead_user: hand_raise[:user], hand_raise_lead_submit_path: hand_raise[:submit_path] }
    end

    # The hand-raise lead form exists only on GitLab.com.
    def orbit_trial_available?
      current_user.present? && ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
    end

    # True only when the user must pick a governing group. `with_fallback` is nil for 0 or 2+
    # candidates (except team members), and the ability needs SaaS, billing, and candidates, so
    # together they mean "2+ candidates, none chosen". Off SaaS the ability is false.
    def orbit_default_group_missing?
      return false unless current_user

      can?(current_user, :update_governing_knowledge_graph_namespace) &&
        current_user.user_preference.knowledge_graph_governing_namespace_with_fallback.nil?
    end

    # The dashboard has no group, so Duo access resolves against the default namespace of the user.
    def duo_accessible?
      return false unless current_user

      namespace = current_user.user_preference.duo_default_namespace_with_fallback
      return false unless namespace

      Ability.allowed?(current_user, :access_duo_features, namespace) &&
        Ability.allowed?(current_user, :access_duo_entry_point)
    end

    def orbit_settings_enabled?
      ::Ai::Orbit::Settings.orbit_in_duo_on?(current_user)
    end

    def admin_orbit_configure_available?
      can?(current_user, :read_knowledge_graph_setting)
    end
  end
end
