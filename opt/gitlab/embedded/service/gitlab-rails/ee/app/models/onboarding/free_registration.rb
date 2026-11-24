# frozen_string_literal: true

module Onboarding
  class FreeRegistration
    extend RegistrationPanelDefaults

    PRODUCT_INTERACTION = 'Personal SaaS Registration'
    private_constant :PRODUCT_INTERACTION
    TRACKING_LABEL = 'free_registration'
    private_constant :TRACKING_LABEL

    # string methods

    def self.tracking_label
      TRACKING_LABEL
    end

    def self.event_label
      nil
    end

    def self.account_created_product_interaction
      nil
    end

    def self.product_interaction
      PRODUCT_INTERACTION
    end

    # internalization methods

    def self.welcome_submit_button_text
      _('Continue')
    end

    def self.setup_for_company_label_text
      _('Who will be using GitLab?')
    end

    def self.setup_for_company_help_text
      _(
        'Try GitLab Ultimate for free and automate tasks with GitLab Duo Agent Platform ' \
          'when you create a new project.'
      )
    end

    def self.get_started_subtext
      nil
    end

    def self.signup_page_image
      'subscription/pipeline'
    end

    def self.signup_page_heading
      s_('InProductMarketing|Ship software faster')
    end

    def self.identity_verification_panel_image
      'subscription/collab'
    end

    def self.identity_verification_panel_heading
      s_('InProductMarketing|Collaborate and accelerate in one place')
    end

    # predicate methods

    def self.eligible_for_iterable_trigger?
      true
    end

    def self.continue_full_onboarding?
      true
    end

    def self.convert_to_automatic_trial?
      true
    end

    def self.show_joining_project?
      true
    end

    def self.apply_trial?
      false
    end

    def self.read_from_stored_user_location?
      false
    end

    def self.preserve_stored_location?
      false
    end

    def self.unification_enabled?
      ::Onboarding.enabled?
    end

    def self.trigger_account_created_iterable?
      false
    end

    def self.redirect_to_customers_portal?
      false
    end
  end
end
