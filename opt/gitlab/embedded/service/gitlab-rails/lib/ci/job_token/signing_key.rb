# frozen_string_literal: true

module Ci
  module JobToken
    # Parsed signing key, reused until the application setting changes.
    class SigningKey < Data.define(:pem, :private_key, :public_key)
      class << self
        def current
          pem = Gitlab::CurrentSettings.ci_job_token_signing_key
          raise 'CI job token signing key is not set' unless pem

          fetch(pem.to_s)
        rescue OpenSSL::PKey::RSAError => error
          Gitlab::ErrorTracking.track_exception(error)
          nil
        end

        private

        def fetch(pem)
          cached = @current
          return cached if cached&.for?(pem)

          @current = parse(pem)
        end

        def parse(pem)
          private_key = OpenSSL::PKey::RSA.new(pem)
          new(pem: pem, private_key: private_key, public_key: private_key.public_key)
        end
      end

      def for?(other_pem)
        pem == other_pem
      end

      def inspect
        "#<#{self.class.name} [FILTERED]>"
      end
      alias_method :to_s, :inspect
    end
  end
end
