# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class NumbersPasswordComplexityRequiredMetric < GenericMetric
          value do
            Gitlab::CurrentSettings.password_number_required
          end
        end
      end
    end
  end
end
