# frozen_string_literal: true

module EE
  module Gitlab
    module Checks
      module IntegrationsCheck
        def validate!
          super

          ::Gitlab::Checks::Integrations::GitGuardianCheck.new(self).validate!
        end
      end
    end
  end
end
