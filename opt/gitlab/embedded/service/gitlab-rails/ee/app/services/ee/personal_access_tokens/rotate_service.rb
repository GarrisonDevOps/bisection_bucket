# frozen_string_literal: true

module EE
  module PersonalAccessTokens
    module RotateService
      extend ::Gitlab::Utils::Override

      private

      override :enforced_expiration_date
      def enforced_expiration_date
        return unless EE::Gitlab::PersonalAccessTokens::ServiceAccountTokenValidator.new(target_user).expiry_enforced?

        max_pat_lifetime_duration =
          EE::Gitlab::PersonalAccessTokens::ExpiryDateCalculator.new(target_user).max_expiry_date

        min_expiry(default_expiration_date, max_pat_lifetime_duration)
      end

      def min_expiry(expiry, limit)
        return expiry unless expiry && limit

        expiry < limit ? expiry : limit
      end
    end
  end
end
