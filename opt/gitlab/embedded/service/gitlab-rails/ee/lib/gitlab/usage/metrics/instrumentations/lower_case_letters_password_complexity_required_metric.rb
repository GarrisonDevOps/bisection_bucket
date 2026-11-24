# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class LowerCaseLettersPasswordComplexityRequiredMetric < GenericMetric
          value do
            Gitlab::CurrentSettings.password_lowercase_required
          end
        end
      end
    end
  end
end
