# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module Domains
        # Identification and authentication failures (OWASP Top 10 A07) lead to
        # account takeover, which no amount of correct authorization downstream
        # can contain. Identity verification and anti-abuse belong here rather
        # than in a domain of their own, because they defend the same boundary.
        module Authentication
          module_function

          def configuration
            {
              name: 'authentication',
              severity: 'high',
              description: N_('RiskAssessment|Authentication, session handling, or identity verification')
            }
          end
        end
      end
    end
  end
end
