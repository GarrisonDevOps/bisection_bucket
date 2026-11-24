# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class PackageRegistryMetadataSyncActivationByTypeMetric < GenericMetric
          def value
            ::PackageMetadata::SyncConfiguration.permitted_purl_types
          end
        end
      end
    end
  end
end
