# frozen_string_literal: true

module IdentityVerifiable
  include Gitlab::Utils::StrongMemoize
  include Gitlab::Experiment::Dsl
  extend ActiveSupport::Concern

  VERIFICATION_METHODS = {
    CREDIT_CARD: 'credit_card',
    PHONE_NUMBER: 'phone',
    EMAIL: 'email'
  }.freeze

  SIGNUP_IDENTITY_VERIFICATION_EXEMPT_METHODS = %w[email].freeze
  PHONE_NUMBER_EXEMPT_METHODS = %w[email credit_card].freeze
  ASSUMED_HIGH_RISK_USER_METHODS = %w[email credit_card phone].freeze
  HIGH_RISK_USER_METHODS = %w[email phone credit_card].freeze
  MEDIUM_RISK_USER_METHODS = %w[email phone].freeze
  LOW_RISK_USER_METHODS = %w[email].freeze
  ACTIVE_USER_METHODS = %w[phone].freeze
  IDENTITY_VERIFICATION_RELEASE_DATE = Date.new(2024, 5, 30)
  IDENTITY_VERIFICATION_FOR_OSS_FROM_DATE = Date.new(2025, 7, 1)

  def signup_identity_verification_enabled?
    return false unless ::Gitlab::Saas.feature_available?(:identity_verification)
    return false unless ::Gitlab::CurrentSettings.email_confirmation_setting_hard?
    return false if ::Gitlab::CurrentSettings.require_admin_approval_after_user_signup

    true
  end

  def active_for_authentication?
    return false unless super

    !signup_identity_verification_enabled? || signup_identity_verified?
  end

  def signup_identity_verified?
    return email_verified? unless signup_identity_verification_enabled?

    # Treat users that have already signed in before as verified if their email
    # is already verified.
    #
    # This prevents the scenario where a user has to verify their identity
    # multiple times. For example:
    #
    # 1. credit_card_verification_enabled application setting is false
    # 2. A user registers, is assigned High risk band, verifies their email as
    # prompted, and starts using GitLab
    # 3. credit_card_verification_enabled application setting is true
    # 4. User signs out and signs in again
    # 5. User is redirected to Identity Verification which requires them to
    # verify their credit card
    return email_verified? if active_user?

    identity_verification_state.values.all?
  end

  def identity_verification_enabled?
    return false unless ::Gitlab::Saas.feature_available?(:identity_verification)

    # When no verification methods are available i.e. both phone number and
    # credit card verifications are disabled
    return false if required_identity_verification_methods.empty?

    true
  end

  def identity_verified?
    return true unless identity_verification_enabled?
    return true unless created_after_require_identity_verification_release_day?
    return bot_identity_verified? unless human?

    # Allow an existing credit card validation to override the identity verification state if
    # credit_card is not a required verification method.
    return true if identity_verification_state.exclude?(VERIFICATION_METHODS[:CREDIT_CARD]) && credit_card_verified?

    identity_verification_state.values.all? || identity_verification_exempt?
  end

  def identity_verification_state
    # Return only the state of required verification methods instead of all
    # methods. This will save us from doing unnecessary queries. E.g. when risk
    # band is 'Low' we only need to call `confirmed?`
    required_identity_verification_methods.index_with do |method|
      verification_state[method].call
    end
  end
  strong_memoize_attr :identity_verification_state

  def required_identity_verification_methods
    methods = determine_required_methods
    methods.select { |method| verification_method_enabled?(method) }
  end

  def credit_card_verified?
    credit_card_validation.present? && !credit_card_validation.used_by_banned_user?
  end

  def add_phone_number_verification_exemption
    return if phone_number_verification_exempt?
    return if phone_verified?

    risk_profile.add_phone_number_verification_exemption
    clear_memoization(:identity_verification_state)
  end

  def toggle_phone_number_verification
    if phone_number_verification_exempt?
      remove_phone_number_verification_exemption
      clear_memoization(:identity_verification_state)
    else
      add_phone_number_verification_exemption
    end
  end

  def identity_verification_exempt?
    return true if risk_profile.identity_verification_exempt?
    return true if enterprise_user?

    # We need identity check for OSS plans to prevent abuse.
    plans = ::GitlabSubscriptions::SystemDefined::Plan::PAID_HOSTED_PLANS
    plans = plans.without(::GitlabSubscriptions::SystemDefined::Plan::OPEN_SOURCE) if id_check_for_oss_enabled?

    include_all_memberships = Feature.enabled?(:identity_verification_paid_membership, self)

    return true if belongs_to_paid_namespace?(
      plans: plans,
      exclude_trials: true,
      include_all_memberships: include_all_memberships
    )

    false
  end

  def offer_phone_number_exemption?
    return false unless verification_method_enabled?('credit_card')
    return false unless verification_method_enabled?('phone')

    phone_required = verification_method_required?(method: VERIFICATION_METHODS[:PHONE_NUMBER])
    cc_required = verification_method_required?(method: VERIFICATION_METHODS[:CREDIT_CARD])

    return false if phone_required && cc_required

    # If phone verification is not required but a phone exemption exists it means the user toggled from
    # verifying with a phone to verifying with a credit card. Returning true if a phone exemption exists
    # will allow the user to toggle back to using phone verification from the credit card form.
    phone_required || phone_number_verification_exempt?
  end

  def verification_method_allowed?(method:)
    return false unless verification_method_required?(method: method)

    # Take all methods that precede <method>. E.g. if <method> is cc and
    # required methods is [email phone cc], then prerequisite methods is
    # [email phone]
    prerequisite_methods = required_identity_verification_methods.take_while { |m| m != method }

    # Get the state of prerequisite methods. E.g. if <method> is cc and state is
    # { email: true, phone: false, cc: false }, then prerequisite methods state
    # is { email: true, phone: false }
    prerequisite_methods_state = identity_verification_state.select { |method| method.in? prerequisite_methods }

    # Check if all prerequisite methods are completed?
    prerequisite_methods_state.values.all?
  end

  def requires_identity_verification_to_create_group?(group)
    return false if group.parent

    reached_top_level_group_limit?
  end

  delegate :arkose_verified?, :assume_low_risk!, :assume_high_risk!, :assumed_high_risk?,
    :add_identity_verification_exemption, :remove_identity_verification_exemption, :phone_number_verification_exempt?,
    :assume_high_risk_if_phone_verification_limit_exceeded!,
    to: :risk_profile
  delegate :high_risk?, :medium_risk?, :low_risk?, :remove_phone_number_verification_exemption,
    to: :risk_profile, private: true

  def id_check_for_oss_enabled?
    Feature.enabled?(:id_check_for_oss, self) && created_after_require_identity_verification_for_oss?
  end

  private

  def verification_method_enabled?(method)
    case method
    when 'phone'
      ::Gitlab::CurrentSettings.phone_verification_enabled &&
        !::Gitlab::ApplicationRateLimiter.peek(:hard_phone_verification_transactions_limit, scope: { scope: :global })
    when 'credit_card'
      ::Gitlab::CurrentSettings.credit_card_verification_enabled
    when 'email'
      !opt_in_flow?
    end
  end

  def active_user?
    last_sign_in_at.present?
  end

  def opt_in_flow?
    active_user? && email_verified?
  end

  def risk_profile
    @risk_profile ||= IdentityVerification::UserRiskProfile.new(self)
  end

  def affected_by_phone_verifications_limit?
    # All users will be required to verify 1. email 2. credit card
    return true if ::Gitlab::ApplicationRateLimiter.peek(:hard_phone_verification_transactions_limit,
      scope: { scope: :global })

    # Actual high risk users will be subject to the same order of required steps
    # as users assumed high risk when the daily phone verification transaction
    # limit is exceeded until it is reset
    return high_risk? if ::Gitlab::ApplicationRateLimiter.peek(:soft_phone_verification_transactions_limit,
      scope: { scope: :global })

    false
  end

  def determine_required_methods
    if opt_in_flow?
      active_user_required_methods
    else
      new_user_required_methods
    end
  end

  def active_user_required_methods
    return PHONE_NUMBER_EXEMPT_METHODS if phone_number_verification_exempt?
    return ASSUMED_HIGH_RISK_USER_METHODS if assumed_high_risk? || affected_by_phone_verifications_limit?

    ACTIVE_USER_METHODS
  end

  def new_user_required_methods
    return SIGNUP_IDENTITY_VERIFICATION_EXEMPT_METHODS if identity_verification_exempt?
    return PHONE_NUMBER_EXEMPT_METHODS if phone_number_verification_exempt?
    return ASSUMED_HIGH_RISK_USER_METHODS if assumed_high_risk? || affected_by_phone_verifications_limit?
    return HIGH_RISK_USER_METHODS if high_risk?
    return MEDIUM_RISK_USER_METHODS if medium_risk?

    LOW_RISK_USER_METHODS
  end

  def verification_method_required?(method:)
    return unless method.in? required_identity_verification_methods

    !identity_verification_state[method]
  end

  def verification_state
    @verification_state ||= {
      credit_card: -> { credit_card_verified? },
      phone: -> { phone_verified? },
      email: -> { email_verified? }
    }.stringify_keys
  end

  def phone_verified?
    phone_number_validation.present? && phone_number_validation.validated?
  end

  def email_verified?
    confirmed?
  end

  def created_top_level_group_count
    ::Namespaces::TopLevelGroupsCreatedCount.new(self).value
  end

  def reached_top_level_group_limit?
    return false if identity_verified?

    created_top_level_group_count >= ::Gitlab::CurrentSettings.unverified_account_group_creation_limit
  end

  def created_after_require_identity_verification_release_day?
    created_at >= IDENTITY_VERIFICATION_RELEASE_DATE
  end

  def created_after_require_identity_verification_for_oss?
    created_at >= IDENTITY_VERIFICATION_FOR_OSS_FROM_DATE
  end

  def bot_identity_verified?
    return true unless project_bot?

    member = members.first
    id_check_for_oss = ::Feature.enabled?(:id_check_for_oss, self)
    if member && member.source.root_ancestor.actual_plan.paid_excluding_trials?(exclude_oss: id_check_for_oss)
      return true
    end

    return false unless created_by.present?
    return false if created_by.banned?

    created_by.identity_verified?
  end
end
