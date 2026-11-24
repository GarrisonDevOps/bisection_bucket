# frozen_string_literal: true

module PackageMetadata
  class CompressedPackageDataObject < CompressedPackageDataObjectBase
    def self.create(data, purl_type)
      new(purl_type: purl_type, **data.transform_keys(&:to_sym))
    end

    attr_accessor :default_licenses, :other_licenses

    def initialize(purl_type:, name:, default_licenses:, lowest_version: nil, highest_version: nil, other_licenses: [])
      @purl_type = purl_type
      @name = name
      @default_licenses = default_licenses
      @lowest_version = lowest_version
      @highest_version = highest_version
      @other_licenses = other_licenses
    end

    def ==(other)
      purl_type == other.purl_type &&
        name == other.name &&
        default_licenses == other.default_licenses &&
        lowest_version == other.lowest_version &&
        highest_version == other.highest_version &&
        other_licenses == other.other_licenses
    end

    def default_identifiers
      default_licenses
    end

    def spdx_identifiers
      (default_licenses + other_licenses.flat_map { |hash| hash['licenses'] })
        .sort.uniq
    end
  end
end
