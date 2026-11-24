# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class DuoFeaturesEnabledMetric < GenericMetric
          def value
            ::Gitlab::CurrentSettings.duo_features_enabled
          end
        end
      end
    end
  end
end
