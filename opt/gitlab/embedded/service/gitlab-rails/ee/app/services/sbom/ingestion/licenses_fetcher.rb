# frozen_string_literal: true

module Sbom
  module Ingestion
    # A component's licenses are sourced from Package Metadata DB unless overridden by licenses passed via SBOM.
    class LicensesFetcher
      include Gitlab::Utils::StrongMemoize

      attr_reader :project, :components

      def initialize(project, occurrence_maps)
        @project = project
        @components = initialize_components(occurrence_maps)
      end

      def fetch(report_component)
        fetched_licenses = licenses.fetch(report_component.key, [])
        fetched_licenses = [unknown_license.dup] if fetched_licenses.empty? && license_scanning_for_cyclonedx_disabled?
        consolidate_unknown_licenses(fetched_licenses)
      end

      private

      def initialize_components(occurrence_maps)
        occurrence_maps.filter_map do |occurrence_map|
          next if occurrence_map.report_component&.purl.blank?

          Hashie::Mash.new(occurrence_map.to_h.slice(:name, :purl_type, :version)
            .merge(path: occurrence_map.input_file_path, licenses: occurrence_map.report_component.licenses))
        end
      end

      def licenses
        return {} if license_scanning_for_cyclonedx_disabled?

        finder = Gitlab::LicenseScanning::PackageLicenses.new(
          components: components,
          project: project
        )
        finder.fetch.each_with_object({}) do |result, hash|
          licenses = result
                       .fetch(:licenses, [])
                       .filter_map { |license| map_from(license) }
                       .sort_by { |license| license[:spdx_identifier] || license[:expression] }
          hash[key_for(result)] = licenses if licenses.present?
        end
      end
      strong_memoize_attr :licenses

      def map_from(license)
        return if license[:spdx_identifier].blank? && license[:expression].blank?

        mapped = license.slice(:name, :spdx_identifier, :url, :expression)
        # Expression-only licenses carry no spdx identifier or name, but the persisted schema and the
        # dependency list (GraphQL LicenseType#name is non-nullable) require a name, so we fall back to
        # the expression string.
        mapped[:name] ||= license[:expression]
        mapped
      end

      def consolidate_unknown_licenses(license_group)
        unknown_count = 0
        license_group.reject! do |license|
          unknown_count += 1 if license[:spdx_identifier] == unknown_license[:spdx_identifier]
        end

        if unknown_count > 0
          license_group << {
            spdx_identifier: unknown_license[:spdx_identifier],
            name: "#{unknown_count} #{unknown_license[:name]}",
            url: unknown_license[:url]
          }
        end

        license_group
      end

      def key_for(result)
        [result.name, result.version, result.purl_type]
      end

      def unknown_license
        Gitlab::LicenseScanning::PackageLicenses::UNKNOWN_LICENSE
      end

      def license_scanning_for_cyclonedx_disabled?
        project.security_setting&.license_scanning_for_cyclonedx_enabled == false
      end
    end
  end
end
