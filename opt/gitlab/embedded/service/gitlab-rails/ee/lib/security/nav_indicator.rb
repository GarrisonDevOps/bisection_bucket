# frozen_string_literal: true

module Security
  module NavIndicator
    # The indicator is a temporary discoverability aid for the 19.6 release and
    # stops rendering after this date. Remove it and its callers once it lapses.
    # See https://gitlab.com/gitlab-org/gitlab/-/work_items/639672
    EXPIRES_ON = Date.new(2026, 12, 19)

    # Callout names are strings to match the enum keys in
    # Users::Callout.feature_names and User#callouts_by_feature_name.
    CALLOUT_FEATURE_NAMES = {
      configuration: 'security_configuration_nav_indicator',
      inventory: 'security_inventory_nav_indicator'
    }.freeze

    def self.visible?(user:, namespace:, page:)
      return false unless user
      return false unless active?
      return false unless ::Feature.enabled?(:security_nav_indicator, namespace.root_ancestor)
      return false if user.dismissed_callout?(feature_name: CALLOUT_FEATURE_NAMES.fetch(page))

      ::Ability.allowed?(user, :apply_security_scan_profiles, namespace)
    end

    def self.active?
      Date.current <= EXPIRES_ON
    end

    def self.show_new_labels?(user:, namespace:)
      return false unless user && active?
      return false unless ::Feature.enabled?(:security_nav_indicator, namespace.root_ancestor)

      ::Ability.allowed?(user, :apply_security_scan_profiles, namespace)
    end
  end
end
