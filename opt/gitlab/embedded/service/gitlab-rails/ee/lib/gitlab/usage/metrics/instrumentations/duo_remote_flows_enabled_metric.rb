# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class DuoRemoteFlowsEnabledMetric < GenericMetric
          def value
            ::Gitlab::CurrentSettings.duo_remote_flows_enabled
          end
        end
      end
    end
  end
end
