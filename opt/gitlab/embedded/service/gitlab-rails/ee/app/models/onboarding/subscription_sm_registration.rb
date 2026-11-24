# frozen_string_literal: true

module Onboarding
  class SubscriptionSmRegistration
    extend RegistrationPanelDefaults

    TRACKING_LABEL = 'subscription_sm_registration'
    private_constant :TRACKING_LABEL
    EVENT_LABEL = 'premium_subscription_sm'
    private_constant :EVENT_LABEL
    ACCOUNT_CREATED_PRODUCT_INTERACTION = 'Direct Purchase Account Creation Premium SM'
    private_constant :ACCOUNT_CREATED_PRODUCT_INTERACTION

    def self.unification_enabled?
      ::Onboarding.enabled?
    end

    def self.trigger_account_created_iterable?
      unification_enabled?
    end

    def self.tracking_label
      TRACKING_LABEL
    end

    def self.event_label
      EVENT_LABEL
    end

    def self.account_created_product_interaction
      ACCOUNT_CREATED_PRODUCT_INTERACTION
    end

    def self.get_started_subtext
      s_('InProductMarketing|Create a GitLab account to purchase the Premium tier of GitLab Self-Managed.')
    end

    def self.read_from_stored_user_location?
      # When unified registration is enabled, the post-verification redirect path is
      # resolved directly via EE::Onboarding::Redirectable#after_sign_up_path, so
      # set_redirect_url must not fall back to the CDot URL stored in
      # stored_location_for(:user).
      !unification_enabled?
    end

    def self.preserve_stored_location?
      true
    end

    def self.redirect_to_customers_portal?
      unification_enabled?
    end
  end
end
