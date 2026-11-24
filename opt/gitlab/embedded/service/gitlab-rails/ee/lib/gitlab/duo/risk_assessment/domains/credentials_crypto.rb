# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module Domains
        # Cryptographic failures (OWASP Top 10 A02) and mishandled credentials
        # are rarely caught by tests, because the code keeps working while the
        # guarantee is gone: a weakened cipher or a token written to a log looks
        # exactly like success.
        module CredentialsCrypto
          module_function

          def configuration
            {
              name: 'credentials_crypto',
              severity: 'critical',
              description: N_('RiskAssessment|Cryptography, key management, or credential handling')
            }
          end
        end
      end
    end
  end
end
