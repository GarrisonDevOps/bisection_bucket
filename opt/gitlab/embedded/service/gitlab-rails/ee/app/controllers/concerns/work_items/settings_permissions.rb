# frozen_string_literal: true

module WorkItems
  module SettingsPermissions
    extend ActiveSupport::Concern
    include Gitlab::Utils::StrongMemoize

    private

    def can_access_work_item_settings?(resource, user)
      if resource.is_a?(Group) && resource.root?
        can?(user, :admin_custom_field, resource) ||
          can?(user, :admin_work_item_lifecycle, resource) ||
          can?(user, :create_work_item_type, resource) ||
          can?(user, :update_work_item_type, resource)
      else
        can?(user, :configure_work_item_type, resource)
      end
    end

    def work_item_settings_available_for_self_managed?
      !::Gitlab::Saas.feature_available?(:namespace_scoped_work_item_types) &&
        License.feature_available?(:configurable_work_item_types)
    end
    strong_memoize_attr :work_item_settings_available_for_self_managed?
  end
end
