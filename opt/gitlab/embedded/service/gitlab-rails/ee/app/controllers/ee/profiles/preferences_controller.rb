# frozen_string_literal: true

module EE::Profiles::PreferencesController
  extend ActiveSupport::Concern
  extend ::Gitlab::Utils::Override

  override :preferences_param_names
  def preferences_param_names
    super + preferences_param_names_ee
  end

  def preferences_param_names_ee
    params_ee = []

    params_ee.push(:duo_default_namespace_id)

    params_ee.concat(orbit_preference_param_names) if orbit_preferences_changed?

    if can?(current_user, :update_governing_knowledge_graph_namespace)
      params_ee.push(:knowledge_graph_governing_namespace_id)
    end

    params_ee.push(:group_view) if License.feature_available?(:security_dashboard)

    params_ee
  end

  private

  def orbit_preference_param_names
    ::Ai::Orbit::Settings::SUBSETTINGS.values.map(&:to_sym)
  end

  def orbit_preferences_changed?
    submitted_preferences = params.require(:user).permit(*orbit_preference_param_names)
    effective_preferences = current_user.user_preference.effective_orbit_settings
    boolean_type = ActiveModel::Type::Boolean.new

    submitted_preferences.to_h.any? do |name, value|
      boolean_type.cast(value) != effective_preferences.fetch(name)
    end
  end
end
