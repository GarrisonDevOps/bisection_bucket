# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class ZoektSearchEnabledMetric < GenericMetric
          value do
            ::Gitlab::CurrentSettings.zoekt_search_enabled?
          end

          available? do
            ::License.feature_available?(:zoekt_code_search)
          end
        end
      end
    end
  end
end
