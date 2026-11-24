# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        module SecretsManagement
          class CountEnrolledNamespacesMetric < DatabaseMetric
            # Namespaces that opted out keep their record, so they must not count as enrolled.
            relation { ::SecretsManagement::NamespaceEnrollment.enabled }

            operation :count
          end
        end
      end
    end
  end
end
