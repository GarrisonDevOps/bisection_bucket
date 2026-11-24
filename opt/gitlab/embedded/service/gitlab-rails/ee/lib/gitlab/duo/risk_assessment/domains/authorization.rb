# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      module Domains
        # Broken access control is the most common real-world web vulnerability
        # (OWASP Top 10 A01), and on a multi-tenant platform an authorization
        # mistake exposes other people's data rather than merely breaking a
        # feature. GitLab treats this as a required approval domain of its own.
        module Authorization
          module_function

          def configuration
            {
              name: 'authorization',
              severity: 'critical',
              description: N_('RiskAssessment|Authorization, access control, or tenant isolation')
            }
          end
        end
      end
    end
  end
end
