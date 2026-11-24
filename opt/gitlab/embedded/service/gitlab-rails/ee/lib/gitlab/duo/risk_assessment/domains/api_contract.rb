# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module Domains
        # A published API is a promise to people who cannot be asked to change.
        # Breaking one fails silently for integrators rather than loudly in CI,
        # which is why it is worth asking about even though most changes to this
        # surface are additive and safe.
        module ApiContract
          module_function

          def configuration
            {
              name: 'api_contract',
              severity: 'high',
              description: N_('RiskAssessment|Public API contract, REST or GraphQL')
            }
          end
        end
      end
    end
  end
end
