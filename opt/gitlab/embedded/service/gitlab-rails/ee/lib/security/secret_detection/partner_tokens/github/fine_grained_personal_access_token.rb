# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Github
        # Verifier for fine-grained GitHub personal access tokens (github_pat_).
        #
        # GET /user works with fine-grained personal access tokens and requires no
        # permission, so a token scoped to one organization still authenticates.
        # https://docs.github.com/en/rest/users/users#get-the-authenticated-user
        class FineGrainedPersonalAccessToken < Base
          private

          def verification_path
            '/user'
          end
        end
      end
    end
  end
end
