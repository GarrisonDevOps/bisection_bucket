# frozen_string_literal: true

module Onboarding
  class UserStatus
    REGISTRATION_KLASSES = {
      ::Onboarding::REGISTRATION_TYPE[:free] => ::Onboarding::FreeRegistration,
      ::Onboarding::REGISTRATION_TYPE[:trial] => ::Onboarding::TrialRegistration,
      ::Onboarding::REGISTRATION_TYPE[:invite] => ::Onboarding::InviteRegistration,
      ::Onboarding::REGISTRATION_TYPE[:subscription] => ::Onboarding::SubscriptionRegistration,
      ::Onboarding::REGISTRATION_TYPE[:subscription_sm] => ::Onboarding::SubscriptionSmRegistration
    }.freeze
    private_constant :REGISTRATION_KLASSES

    attr_reader :registration_type

    # string delegations
    delegate :product_interaction, to: :registration_type
    # predicate delegations
    delegate :apply_trial?, :eligible_for_iterable_trigger?, to: :registration_type

    def initialize(user)
      @user = user

      @registration_type = calculate_registration_type_klass
    end

    def free_registration?
      user&.onboarding_status_registration_type == REGISTRATION_TYPE[:free]
    end

    def trial_registration?
      user&.onboarding_status_registration_type == registration_type_trial
    end

    def invite_registration?
      user&.onboarding_status_registration_type == REGISTRATION_TYPE[:invite]
    end

    def subscription_registration?
      user&.onboarding_status_registration_type == REGISTRATION_TYPE[:subscription]
    end

    private

    attr_reader :user

    def calculate_registration_type_klass
      return ::Onboarding::AutomaticTrialRegistration if automatic_trial?

      REGISTRATION_KLASSES.fetch(user&.onboarding_status_registration_type, ::Onboarding::FreeRegistration)
    end

    def automatic_trial?
      trial_registration? && !initial_trial?
    end

    def initial_trial?
      user.onboarding_status_initial_registration_type == registration_type_trial
    end

    def registration_type_trial
      REGISTRATION_TYPE[:trial]
    end
  end
end
