# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class DuoAvailabilityMetric < GenericMetric
          def value
            ::Gitlab::CurrentSettings.duo_availability.to_s
          end
        end
      end
    end
  end
end
