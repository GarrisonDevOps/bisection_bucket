# frozen_string_literal: true

module Onboarding
  class TrialRegistration
    extend RegistrationPanelDefaults

    PRODUCT_INTERACTION = 'SaaS Trial'
    private_constant :PRODUCT_INTERACTION
    ACCOUNT_CREATED_PRODUCT_INTERACTION = 'SaaS Trial Account Creation'
    private_constant :ACCOUNT_CREATED_PRODUCT_INTERACTION
    TRACKING_LABEL = 'trial_registration'
    private_constant :TRACKING_LABEL

    # string methods

    def self.tracking_label
      TRACKING_LABEL
    end

    def self.event_label
      nil
    end

    def self.account_created_product_interaction
      ACCOUNT_CREATED_PRODUCT_INTERACTION
    end

    def self.product_interaction
      PRODUCT_INTERACTION
    end

    # internalization methods

    def self.welcome_submit_button_text
      _('Continue')
    end

    def self.setup_for_company_label_text
      _('Who will be using this GitLab trial?')
    end

    def self.setup_for_company_help_text
      nil
    end

    def self.get_started_subtext
      # rubocop:disable CodeReuse/ServiceClass -- PORO, not an AR model; reuses the canonical trial duration service
      duration = ::GitlabSubscriptions::TrialDurationService.new.execute
      # rubocop:enable CodeReuse/ServiceClass

      if unification_enabled?
        format(
          s_(
            "InProductMarketing|Start your free %{duration} day trial today, no credit card required. " \
              "You'll have full access to our most advanced features, including GitLab Duo Agent Platform."
          ),
          duration: duration
        )
      else
        format(
          s_("InProductMarketing|Try our most advanced features, including GitLab Duo Agent Platform " \
            "to automate development tasks with AI agents. After your %{duration}-day trial, " \
            "continue with free features or upgrade to unlock the full value of GitLab."),
          duration: duration
        )
      end
    end

    # predicate methods

    def self.eligible_for_iterable_trigger?
      false
    end

    def self.continue_full_onboarding?
      true
    end

    def self.convert_to_automatic_trial?
      false
    end

    def self.show_joining_project?
      false
    end

    def self.apply_trial?
      true
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
      unification_enabled?
    end

    def self.redirect_to_customers_portal?
      false
    end
  end
end
