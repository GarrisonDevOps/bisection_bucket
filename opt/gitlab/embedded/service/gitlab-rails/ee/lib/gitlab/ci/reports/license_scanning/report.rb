# frozen_string_literal: true

module Gitlab
  module Ci
    module Reports
      module LicenseScanning
        class Report
          delegate :empty?, :fetch, :[], to: :found_licenses
          attr_accessor :version

          def initialize(version: '1.0')
            @version = version
            @found_licenses = {}
          end

          def major_version
            version.split('.')[0]
          end

          def licenses
            found_licenses.values.sort_by { |license| license.name.downcase }
          end

          def license_names
            found_licenses.values.map(&:name)
          end

          def add_license(id:, name:, url: '')
            add(::Gitlab::Ci::Reports::LicenseScanning::License.new(
              id: id, name: name, url: url))
          end

          def add(license)
            found_licenses[license.canonical_id] ||= license
          end

          def dependency_names
            found_licenses.values.flat_map(&:dependencies).map(&:name).uniq
          end

          def by_license_name(name)
            licenses.find { |license| license.name.casecmp?(name) }
          end

          def diff_with(other_report)
            base = licenses
            head = other_report&.licenses || []

            {
              added: (head - base),
              unchanged: (base & head),
              removed: (base - head)
            }
          end

          def diff_with_including_new_dependencies_for_unchanged_licenses(other_report, include_version: true)
            base = licenses
            head = other_report&.licenses || []

            diff_with(other_report).tap do |licenses|
              add_new_dependencies_for_unchanged_licenses(base, head, licenses, include_version)
            end
          end

          private

          def add_new_dependencies_for_unchanged_licenses(base, head, licenses, include_version)
            licenses[:unchanged].each do |license|
              new_dependencies_for_existing_license = new_dependencies_for_existing_license(base, head, license,
                include_version)
              next unless new_dependencies_for_existing_license.present?

              licenses[:added] << new_license_with_dependencies(license, new_dependencies_for_existing_license)
            end
          end

          def new_dependencies_for_existing_license(base, head, license, include_version)
            license_name = license.name
            head_license = head.find { |license| license.name == license_name }
            base_license = base.find { |license| license.name == license_name }
            return unless head_license && base_license

            head_license_dependencies = head_license.dependencies || Set.new
            base_license_dependencies = base_license.dependencies || Set.new

            if include_version
              head_license_dependencies - base_license_dependencies
            else
              subtract_dependencies_without_version(head_license_dependencies, base_license_dependencies)
            end
          end

          def subtract_dependencies_without_version(head_dependencies, base_dependencies)
            head_dependencies.reject do |head_dep|
              base_dependencies.any? do |base_dep|
                head_dep.name == base_dep.name &&
                  head_dep.package_manager == base_dep.package_manager &&
                  head_dep.purl_type == base_dep.purl_type
              end
            end
          end

          def new_license_with_dependencies(license, new_dependencies_for_existing_license)
            ::Gitlab::Ci::Reports::LicenseScanning::License.new(id: license.id, name: license.name,
              url: license.url).tap do |new_license|
              new_dependencies_for_existing_license.each do |dependency|
                new_license.add_dependency(**dependency.instance_values.with_indifferent_access)
              end
            end
          end

          attr_reader :found_licenses
        end
      end
    end
  end
end
