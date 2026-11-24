# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class DuoFoundationalFlowsEnabledMetric < GenericMetric
          def value
            ::Gitlab::CurrentSettings.duo_foundational_flows_enabled
          end
        end
      end
    end
  end
end
