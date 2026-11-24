# frozen_string_literal: true

module CloudConnector
  module StatusChecks
    module Probes
      class TokenProbe < BaseProbe
        extend ::Gitlab::Utils::Override

        validate :check_access_token_exists
        validate :decode_token
        validate :validate_expiration_date
        after_validation :collect_token_details

        private

        attr_accessor :decoded_token

        override :success_message
        def success_message
          _("Access credentials are valid.")
        end

        def token
          @token ||= ::CloudConnector::ServiceAccessToken.last
        end

        def check_access_token_exists
          errors.add(:base, missing_access_token_text) unless token
        end

        def decode_token
          return if token.nil?

          begin
            @decoded_token = JWT.decode(token.token, nil, false).first
            details.add(:decode, 'Successful')
          rescue JWT::DecodeError => e
            details.add(:decode, "Failed with message: #{e.message}")
            errors.add(:base, invalid_access_token_text)
            @decoded_token = nil
          end
        end

        def validate_expiration_date
          return if decoded_token.nil?

          exp = Time.at(decoded_token['exp'].to_i).utc
          expired = exp.past?
          details.add(:expired, expired)
          details.add(:expires_at, exp)

          errors.add(:base, expired_access_token_text) if expired
        end

        def collect_token_details
          return unless decoded_token

          details.add(:created_at, token.created_at)
          details.add(:token, decoded_token)
        end

        def missing_access_token_text
          format(_("Access credentials not found. %{cta}"), cta: synchronize_subscription_cta)
        end

        def invalid_access_token_text
          format(_("Invalid access credentials. %{cta}"), cta: synchronize_subscription_cta)
        end

        def expired_access_token_text
          format(_("Access credentials expired. %{cta}"), cta: synchronize_subscription_cta)
        end

        def synchronize_subscription_cta
          _('Synchronize your subscription.')
        end
      end
    end
  end
end
