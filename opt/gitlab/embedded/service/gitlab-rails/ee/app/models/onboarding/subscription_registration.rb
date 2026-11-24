# frozen_string_literal: true

module Onboarding
  class SubscriptionRegistration
    extend RegistrationPanelDefaults

    TRACKING_LABEL = 'subscription_registration'
    private_constant :TRACKING_LABEL
    EVENT_LABEL = 'premium_subscription_com'
    private_constant :EVENT_LABEL
    ACCOUNT_CREATED_PRODUCT_INTERACTION = 'Direct Purchase Account Creation Premium Dotcom'
    private_constant :ACCOUNT_CREATED_PRODUCT_INTERACTION

    # string methods

    def self.tracking_label
      TRACKING_LABEL
    end

    def self.event_label
      EVENT_LABEL
    end

    def self.account_created_product_interaction
      ACCOUNT_CREATED_PRODUCT_INTERACTION
    end

    # internalization methods
    def self.get_started_subtext
      _("Create a GitLab account to purchase GitLab Premium.")
    end

    # predicate methods

    def self.read_from_stored_user_location?
      true
    end

    def self.preserve_stored_location?
      true
    end

    def self.unification_enabled?
      ::Onboarding.enabled?
    end

    def self.trigger_account_created_iterable?
      unification_enabled?
    end

    def self.redirect_to_customers_portal?
      false
    end
  end
end
