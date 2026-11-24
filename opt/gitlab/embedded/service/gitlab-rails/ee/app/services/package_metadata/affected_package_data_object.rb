# frozen_string_literal: true

module PackageMetadata
  class AffectedPackageDataObject
    def self.create(hash, purl_type)
      affected_package = hash
      affected_package['package_name'] = affected_package.delete('name') if affected_package.has_key?('name')
      new(purl_type: purl_type, **affected_package.transform_keys(&:to_sym))
    end

    attr_accessor :purl_type, :package_name, :affected_range, :solution, :fixed_versions, :distro_version,
      :versions, :overridden_advisory_fields, :pm_advisory_id

    # Unknown keys are collected here and thrown away, so a field added upstream
    # doesn't discard the whole advisory.
    # rubocop:disable Metrics/ParameterLists -- keyword per exporter field
    def initialize(
      purl_type:, package_name:, affected_range:, solution: '', fixed_versions: '', distro: '',
      versions: [], overridden_advisory_fields: {}, **_unknown_fields)
      # rubocop:enable Metrics/ParameterLists
      @purl_type = purl_type
      @package_name = package_name
      @affected_range = affected_range
      @solution = solution
      @fixed_versions = fixed_versions
      # The field name from the advisory exporter is `distro`, however, the name used in this codebase is
      # `distro_version`. This field contains both the distro name and version. For example: `debian 12` or
      # `alpine 3.7`.
      @distro_version = distro
      @versions = versions
      @overridden_advisory_fields = overridden_advisory_fields
    end
  end
end
