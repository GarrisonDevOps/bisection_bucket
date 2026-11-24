# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Github
        # Verifier for classic GitHub personal access tokens (ghp_).
        #
        # GET /user authenticates as the token owner, so a 200 proves the credential is
        # live. Scopes change how much of the body GitHub returns, never the status code.
        # https://docs.github.com/en/rest/users/users#get-the-authenticated-user
        class PersonalAccessToken < Base
          private

          def verification_path
            '/user'
          end
        end
      end
    end
  end
end
