# frozen_string_literal: true

module Gitlab
  module Ci
    module Parsers
      module Security
        class DependencyScanning < Common
          private

          def create_location(location_data)
            ::Gitlab::Ci::Reports::Security::Locations::DependencyScanning.new(
              file_path: location_data['file'],
              package_name: normalized_package_name(location_data),
              package_version: location_data.dig('dependency', 'version'),
              files: location_data['files'])
          end

          def normalized_package_name(location_data)
            package_name = location_data.dig('dependency', 'package', 'name')

            return package_name unless python_scanner?

            ::Sbom::PackageUrl::Normalizer.new(type: 'pypi', text: package_name).normalize_name
          end

          def python_scanner?
            report_data
              .dig("scan", "analyzer", "id")
              &.include?('python')
          end
        end
      end
    end
  end
end
