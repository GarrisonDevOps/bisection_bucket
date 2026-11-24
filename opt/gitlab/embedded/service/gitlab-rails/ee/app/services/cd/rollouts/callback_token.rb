# frozen_string_literal: true

module Cd
  module Rollouts
    # Bearer token the Argo Rollouts deploy driver presents on workflow-event
    # callbacks (API::Cd::Rollouts); driver can't reach Rails via GraphQL/PAT.
    # Signed with Gitlab::Kas's shared secret, scoped to one rollout via `rollout_id`.
    class CallbackToken
      ISSUER = 'gitlab-rails'
      AUDIENCE = 'gitlab-cd-rollout-callback'
      # TODO: 60 days is a stopgap until callback auth has a proper renewal/rotation story.
      EXPIRE_IN = 60.days

      def self.encode(rollout)
        token = JSONWebToken::HMACToken.new(Gitlab::Kas.secret)
        token.issuer = ISSUER
        token.audience = AUDIENCE
        token.expire_time = Time.current + EXPIRE_IN
        token[:rollout_id] = rollout.id
        token.encoded
      end

      def self.matches?(token, rollout)
        return false if token.blank?

        payload, = Gitlab::Kas.decode_jwt(token, issuer: ISSUER, audience: AUDIENCE)
        payload['rollout_id'] == rollout.id
      rescue JWT::DecodeError
        false
      end
    end
  end
end
