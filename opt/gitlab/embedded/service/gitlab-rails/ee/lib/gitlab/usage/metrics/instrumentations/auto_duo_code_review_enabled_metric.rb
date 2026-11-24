# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class AutoDuoCodeReviewEnabledMetric < GenericMetric
          def value
            ::Gitlab::CurrentSettings.auto_duo_code_review_enabled
          end
        end
      end
    end
  end
end
