# frozen_string_literal: true

module PhoneVerification
  module Users
    class RecordUserDataService
      def initialize(user:, phone_verification_record:, risk_result:)
        @user = user
        @user_risk_profile = ::IdentityVerification::UserRiskProfile.new(user)
        @phone_verification_record = phone_verification_record

        # Ensure the minimum score from the intelligence API is 1 since this value is used to determine if
        # the intelligence API has already been queried.
        @risk_score = [risk_result[:risk_score], 1].max
      end

      def execute
        phone_verification_record.risk_score = risk_score
        store_risk_score(risk_score)

        return assume_high_risk! if assume_high_risk?

        ServiceResponse.success
      end

      private

      attr_reader :user, :user_risk_profile, :phone_verification_record, :risk_score

      def error_related_to_high_risk_user
        ServiceResponse.error(message: 'Phone verification high-risk user', reason: :related_to_high_risk_user)
      end

      def store_risk_score(risk_score)
        # nop
      end

      def assume_high_risk?
        return false if user.credit_card_verified?
        return false if user_risk_profile.assumed_high_risk?

        risk_score > ::IdentityVerification::UserRiskProfile::TELESIGN_HIGH_RISK_THRESHOLD
      end

      def assume_high_risk!
        user_risk_profile.assume_high_risk!(reason: 'Telesign intelligence identified user as high risk')
        phone_verification_record.save!

        error_related_to_high_risk_user
      end
    end
  end
end
