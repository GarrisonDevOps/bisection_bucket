# frozen_string_literal: true

module Gitlab
  module Sessions
    # When the remember me cookie stops signing the user back in, so an open page can keep a
    # remembered user's session alive instead of warning them it expired.
    class RememberMe
      class << self
        # nil when the cookie is absent or would be rejected (revoked, expired, or remember me
        # disabled by the admin), using Devise's own check.
        def expires_at(user, cookies)
          return unless user.respond_to?(:remember_me?)

          _, token, generated_at = cookies.signed[cookie_key(user)]
          return unless user.remember_me?(token, generated_at)

          # Devise writes the issue time as an epoch float string, and remember_me? has just
          # accepted it, so it parses without further checks.
          generated_at.to_f.to_i + user.class.remember_for.to_i
        end

        private

        def cookie_key(user)
          user.rememberable_options.fetch(:key, 'remember_user_token')
        end
      end
    end
  end
end
