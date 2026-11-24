# frozen_string_literal: true

module Authn
  module Tokens
    class StatelessAccessToken
      # StatelessAccessToken has no DB row, so revocation is a Redis denylist
      # keyed on jti, with deny! deriving its own TTL from the token's
      # expires_at (clamped to at least 1s) so callers can't pass a mismatch.
      class Denylist
        KEY_PREFIX = 'stateless_access_token:revoked:'

        class << self
          def deny!(token)
            return if token&.id.blank?

            ttl = [(token.expires_at - Time.current).to_i, 1].max

            Gitlab::Redis::SharedState.with do |redis|
              redis.set(key(token.id), 1, ex: ttl)
            end
          end

          def denied?(jti)
            return false if jti.blank?

            Gitlab::Redis::SharedState.with do |redis|
              redis.exists?(key(jti)) # rubocop:disable CodeReuse/ActiveRecord -- not ActiveRecord, Redis#exists?
            end
          end

          private

          def key(jti)
            "#{KEY_PREFIX}#{jti}"
          end
        end
      end
    end
  end
end
