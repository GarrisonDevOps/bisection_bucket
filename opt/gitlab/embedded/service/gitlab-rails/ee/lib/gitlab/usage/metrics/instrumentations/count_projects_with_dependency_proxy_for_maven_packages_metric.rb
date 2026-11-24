# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountProjectsWithDependencyProxyForMavenPackagesMetric < DatabaseMetric
          operation :distinct_count, column: :project_id

          relation do
            ::DependencyProxy::Packages::Setting.enabled
              .where.not(maven_external_registry_url: nil)
          end
        end
      end
    end
  end
end
