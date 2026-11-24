# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class ZoektNodeVersionMetric < GenericMetric
          value do
            # Returns the maximum version string across online Zoekt nodes.
            # This relies on lexicographic comparison of the date-prefix format (YYYY.MM.DD-vX.Y.Z).
            # The date prefix ensures correct ordering: newer versions have later dates and sort higher.
            ::Search::Zoekt::Node.online.maximum("metadata->>'version'")
          end

          available? do
            ::License.feature_available?(:zoekt_code_search)
          end
        end
      end
    end
  end
end
