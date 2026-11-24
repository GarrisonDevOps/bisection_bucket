# frozen_string_literal: true

module Search
  module Zoekt
    module JwtAuth
      ISSUER = 'gitlab'
      AUDIENCE = 'gitlab-zoekt'
      TOKEN_EXPIRE_TIME = 5.minutes

      class << self
        def secret_token
          Gitlab::Shell.secret_token
        end

        def jwt_token
          current_time = Time.current.to_i
          payload = {
            iat: current_time,
            iss: ISSUER,
            aud: AUDIENCE
          }

          payload[:exp] = current_time + TOKEN_EXPIRE_TIME.to_i unless skip_expiration?

          JWT.encode(payload, secret_token, 'HS256')
        end

        def authorization_header
          "Bearer #{jwt_token}"
        end

        private

        def skip_expiration?
          return false unless Rails.env.development? || Rails.env.test?

          Gitlab::Utils.to_boolean(ENV['ZOEKT_JWT_SKIP_EXPIRY'])
        end
      end
    end
  end
end
