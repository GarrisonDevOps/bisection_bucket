# frozen_string_literal: true

module PackageMetadata
  class Package < ApplicationRecord
    DEFAULT_LICENSES_IDX = 0
    LOWEST_VERSION_IDX = 1
    HIGHEST_VERSION_IDX = 2
    OTHER_LICENSES_IDX = 3

    # Our license-db exporter exports license and advisory data from the
    # external license-db to a public GCP bucket for ingestion by the GitLab
    # Rails application. Using the same regular expression in both projects
    # ensures consistency across system boundaries.
    # https://pkg.go.dev/github.com/hashicorp/go-version#pkg-constants
    # rubocop: disable Layout/LineLength
    VERSION_REGEXP_RAW = /v?([0-9]+(\.[0-9]+)*?)(-([0-9]+[0-9A-Za-z\-~]*(\.[0-9A-Za-z\-~]+)*)|(-?([A-Za-z\-~]+[0-9A-Za-z\-~]*(\.[0-9A-Za-z\-~]+)*)))?(\+([0-9A-Za-z\-~]+(\.[0-9A-Za-z\-~]+)*))??/
    # rubocop: enable Layout/LineLength

    include BulkInsertSafe

    enum :purl_type, ::Enums::Sbom.purl_types

    validates :purl_type, presence: true
    validates :name, presence: true, length: { maximum: 255 }
    validates :licenses, json_schema: { filename: 'pm_package_licenses' }, if: -> { licenses.present? }

    def license_ids_for(version:)
      # if the package metadata has not yet completed syncing, then the licenses field
      # might be nil, in which case we return an empty array.
      return [] if licenses.blank?

      matching_other_license_ids(version: version) || default_license_ids(version: version)
    end

    # Takes an array of components and uses the purl_type and name fields to search for matching
    # packages
    def self.packages_for(components:)
      search_fields = [arel_table[:purl_type], arel_table[:name]]

      component_tuples = components.map do |component|
        purl_type_int = ::Enums::Sbom.purl_types[component.purl_type]
        component_tuple = [purl_type_int, component.name].map { |c| Arel::Nodes.build_quoted(c) }
        Arel::Nodes::Grouping.new(component_tuple)
      end

      where(Arel::Nodes::In.new(Arel::Nodes::Grouping.new(search_fields), component_tuples))
    end

    private

    def matching_other_license_ids(version:)
      other_licenses.each do |other_license|
        license_ids = other_license[0]
        versions = other_license[1]

        return license_ids if versions.include?(version)
      end

      nil
    end

    def lowest_version
      licenses[LOWEST_VERSION_IDX]
    end

    def highest_version
      licenses[HIGHEST_VERSION_IDX]
    end

    def other_licenses
      licenses[OTHER_LICENSES_IDX]
    end

    def default_license_ids(version:)
      # if the version does not match the exporter format, return an empty array.
      # https://gitlab.com/gitlab-org/gitlab/-/issues/410434
      return [] unless VERSION_REGEXP_RAW.match(version)

      # if the given version is greater than the highest known version or lower
      # than the lowest known version, then the version is not supported, in
      # which case we return an empty array.
      return [] unless version_in_default_licenses_range?(version)

      licenses[DEFAULT_LICENSES_IDX]
    end

    def version_in_default_licenses_range?(input_version)
      type =
        case purl_type
        when 'golang'
          'go'
        when 'composer'
          'packagist'
        else
          purl_type
        end
      # Remove 'v' from version string(if present) before comparison.
      interval = SemverDialects::IntervalParser.parse(type, "=#{input_version.delete_prefix('v')}")
      range = SemverDialects::IntervalSet.new
      range.add(SemverDialects::IntervalParser.parse(type, "<#{lowest_version.delete_prefix('v')}")) if lowest_version

      range.add(SemverDialects::IntervalParser.parse(type, ">#{highest_version.delete_prefix('v')}")) if highest_version

      !range.overlaps_with?(interval)
    rescue SemverDialects::InvalidConstraintError, SemverDialects::UnsupportedPackageTypeError
      false
    end
  end
end
