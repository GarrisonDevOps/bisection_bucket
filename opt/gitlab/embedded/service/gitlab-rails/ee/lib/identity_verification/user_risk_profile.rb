# frozen_string_literal: true

module IdentityVerification
  class UserRiskProfile
    include Gitlab::Utils::StrongMemoize

    attr_reader :user

    ASSUMED_HIGH_RISK_ATTR_KEY = 'assumed_high_risk_reason'
    ASSUMED_LOW_RISK_ATTR_KEY = 'assumed_low_risk_reason'

    CUSTOM_ATTR_KEYS = [
      UserCustomAttribute::ARKOSE_RISK_BAND,
      UserCustomAttribute::IDENTITY_VERIFICATION_EXEMPT,
      UserCustomAttribute::IDENTITY_VERIFICATION_PHONE_EXEMPT,
      ASSUMED_HIGH_RISK_ATTR_KEY,
      ASSUMED_LOW_RISK_ATTR_KEY
    ].freeze

    # https://developer.telesign.com/enterprise/docs/intelligence-get-started#score-scales
    TELESIGN_HIGH_RISK_THRESHOLD = 600

    def initialize(user)
      @user = user
    end

    def arkose_verified?
      arkose_risk_band.present? || assumed_low_risk?
    end

    def assume_low_risk!(reason:)
      create_custom_attribute(ASSUMED_LOW_RISK_ATTR_KEY, reason)
      log_assumed_risk(level: 'low', reason: reason)
    end

    def assume_high_risk!(reason:)
      create_custom_attribute(ASSUMED_HIGH_RISK_ATTR_KEY, reason)
      log_assumed_risk(level: 'high', reason: reason)
    end

    def assumed_high_risk?
      custom_attribute(ASSUMED_HIGH_RISK_ATTR_KEY).present?
    end

    def medium_risk?
      arkose_risk_band == ::Arkose::VerifyResponse::RISK_BAND_MEDIUM.downcase
    end

    def high_risk?
      arkose_risk_band == ::Arkose::VerifyResponse::RISK_BAND_HIGH.downcase
    end

    def identity_verification_exempt?
      custom_attribute(UserCustomAttribute::IDENTITY_VERIFICATION_EXEMPT).present?
    end

    def add_identity_verification_exemption(reason)
      create_custom_attribute(UserCustomAttribute::IDENTITY_VERIFICATION_EXEMPT, reason)
    end

    def remove_identity_verification_exemption
      destroy_custom_attribute(UserCustomAttribute::IDENTITY_VERIFICATION_EXEMPT)
    end

    def phone_number_verification_exempt?
      exemption_attr = custom_attribute(UserCustomAttribute::IDENTITY_VERIFICATION_PHONE_EXEMPT)
      exemption_attr.present? && ActiveModel::Type::Boolean.new.cast(exemption_attr.value)
    end

    def add_phone_number_verification_exemption
      create_custom_attribute(UserCustomAttribute::IDENTITY_VERIFICATION_PHONE_EXEMPT, true.to_s)
    end

    def remove_phone_number_verification_exemption
      destroy_custom_attribute(UserCustomAttribute::IDENTITY_VERIFICATION_PHONE_EXEMPT)
    end

    def assume_high_risk_if_phone_verification_limit_exceeded!
      return unless user

      return unless ::Gitlab::ApplicationRateLimiter.peek(:soft_phone_verification_transactions_limit,
        scope: { scope: :global })

      user.assume_high_risk!(reason: 'Phone verification daily transaction limit exceeded')
    end

    private

    def user_custom_attributes
      user.custom_attributes.by_key(CUSTOM_ATTR_KEYS).to_a
    end
    strong_memoize_attr :user_custom_attributes

    def custom_attribute(key)
      user_custom_attributes.find { |a| a.key == key }
    end

    def create_custom_attribute(key, value)
      result = ::UserCustomAttribute.upsert_custom_attribute(user_id: user.id, key: key, value: value)
      clear_memoization(:user_custom_attributes)
      !result.empty?
    end

    def destroy_custom_attribute(key)
      custom_attribute(key).tap do |custom_attr|
        custom_attr&.destroy && clear_memoization(:user_custom_attributes)
      end
    end

    def assumed_low_risk?
      custom_attribute(ASSUMED_LOW_RISK_ATTR_KEY).present?
    end

    def arkose_risk_band
      risk_band_attr = custom_attribute(UserCustomAttribute::ARKOSE_RISK_BAND)
      return unless risk_band_attr.present?

      risk_band_attr.value.downcase
    end

    def log_assumed_risk(level:, reason:)
      Gitlab::AppLogger.info(
        message: self.class.to_s,
        event: "User assumed #{level} risk.",
        reason: reason,
        user_id: user.id,
        username: user.username
      )
    end
  end
end
