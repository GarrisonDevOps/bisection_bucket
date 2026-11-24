# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class UpperCaseLettersPasswordComplexityRequiredMetric < GenericMetric
          value do
            Gitlab::CurrentSettings.password_uppercase_required
          end
        end
      end
    end
  end
end
