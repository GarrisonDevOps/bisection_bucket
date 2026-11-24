# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class OrbitServiceConfiguredMetric < GenericMetric
          value do
            ::Analytics::KnowledgeGraph.service_configured?
          end
        end
      end
    end
  end
end
