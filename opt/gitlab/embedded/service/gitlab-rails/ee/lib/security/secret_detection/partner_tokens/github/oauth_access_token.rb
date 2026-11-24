# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Github
        # Verifier for GitHub OAuth access tokens (gho_).
        #
        # An OAuth app token authenticates as the user who granted it, so GET /user
        # applies. The OAuth app endpoint would need the app's client secret, which a
        # leaked token does not give us.
        # https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
        class OauthAccessToken < Base
          private

          def verification_path
            '/user'
          end
        end
      end
    end
  end
end
