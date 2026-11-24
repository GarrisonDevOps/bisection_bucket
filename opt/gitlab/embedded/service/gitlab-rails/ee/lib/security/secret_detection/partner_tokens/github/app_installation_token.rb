# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      module Github
        # Verifier for legacy GitHub App installation tokens (v1. plus 40 hex characters).
        #
        # Installation tokens are server-to-server, so GET /user does not accept them.
        # The installation endpoint does, and needs no permission.
        # https://docs.github.com/en/rest/apps/installations#list-repositories-accessible-to-the-app-installation
        class AppInstallationToken < Base
          private

          def verification_path
            '/installation/repositories'
          end
        end
      end
    end
  end
end
