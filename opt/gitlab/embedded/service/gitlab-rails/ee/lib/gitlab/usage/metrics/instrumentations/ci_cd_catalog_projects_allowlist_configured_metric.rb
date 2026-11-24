# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CiCdCatalogProjectsAllowlistConfiguredMetric < GenericMetric
          value do
            ::Gitlab::CurrentSettings.ci_cd_catalog_projects_allowlist.present?
          end
        end
      end
    end
  end
end
