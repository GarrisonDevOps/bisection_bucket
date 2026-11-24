# frozen_string_literal: true

module PackageMetadata
  class AdvisoryDataObject
    FALSE_POSITIVE_TITLE = 'false positive'
    def self.create(data, purl_type)
      advisory = data['advisory'].clone
      advisory['advisory_xid'] = advisory.delete('id') if advisory.has_key?('id')

      source = advisory.delete('source')
      unless Enums::PackageMetadata::ADVISORY_SOURCES.has_key?(source)
        raise ArgumentError, "Unsupported advisory source #{source}"
      end

      advisory['source_xid'] = source
      advisory['cve'] = extract_cve(advisory['identifiers'])
      advisory['cvss_v4'] = cvss_v4(data)

      packages = data['packages'].clone
      raise ArgumentError, 'Missing packages attribute' unless packages

      affected_packages = create_affected_packages(packages, purl_type)
      new(**advisory.transform_keys(&:to_sym), affected_packages: affected_packages)
    end

    def self.create_affected_packages(packages, purl_type)
      packages.map do |package_hash|
        AffectedPackageDataObject.create(package_hash, purl_type)
      end
    end

    # v2 carries cvss_v4 in an additional_fields wrapper beside the advisory.
    def self.cvss_v4(data)
      data.dig('additional_fields', 'advisory', 'cvss_v4')
    end

    def self.extract_cve(identifiers)
      return unless identifiers

      cve_identifier = identifiers.find { |identifier| identifier['type']&.casecmp?('cve') }
      cve_identifier['name'] if cve_identifier
    end

    private_class_method :extract_cve

    attr_accessor :advisory_xid, :source_xid, :published_date, :title, :description, :cvss_v2, :cvss_v3, :cvss_v4,
      :urls, :identifiers, :affected_packages, :cve

    # Unknown keys are collected here and thrown away, so a field added upstream
    # doesn't discard the whole advisory.
    # rubocop:disable Metrics/ParameterLists
    def initialize(
      advisory_xid:, source_xid:, published_date:, title: '', description: '', cvss_v2: nil, cvss_v3: nil, cvss_v4: nil,
      urls: [], identifiers: [], affected_packages: [], cve: nil, **_unknown_fields)
      # rubocop:enable Metrics/ParameterLists
      @advisory_xid = advisory_xid
      @source_xid = source_xid
      @published_date = published_date
      @title = title
      @description = description
      @cvss_v2 = cvss_v2
      @cvss_v3 = cvss_v3
      @cvss_v4 = cvss_v4
      @urls = urls
      @identifiers = identifiers.map { |ident| ident.transform_keys(&:to_sym) }
      @affected_packages = affected_packages
      @cve = cve
    end

    def false_positive?
      source_xid.to_s == 'glad' && title.to_s.casecmp?(FALSE_POSITIVE_TITLE)
    end
  end
end
