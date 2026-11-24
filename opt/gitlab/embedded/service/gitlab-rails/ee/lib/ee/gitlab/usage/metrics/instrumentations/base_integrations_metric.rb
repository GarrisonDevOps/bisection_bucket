# frozen_string_literal: true

module EE
  module Gitlab
    module Usage
      module Metrics
        module Instrumentations
          module BaseIntegrationsMetric
            extend ::Gitlab::Utils::Override

            override :allowed_types
            def allowed_types
              ::Integration.available_integration_names(
                include_dev: false,
                include_disabled: true,
                include_blocked_by_settings: true
              )
            end
          end
        end
      end
    end
  end
end
