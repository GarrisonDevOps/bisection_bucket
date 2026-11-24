# frozen_string_literal: true

module Security
  module DependencyFirewall
    class FetchPackageVulnerabilitiesService
      include Gitlab::VulnerabilityScanning::AdvisoryUtils

      UNKNOWN_SEVERITY = 'unknown'

      def initialize(name:, purl_type:, version:)
        @name = name
        @purl_type = purl_type
        @version = version
      end

      def execute
        affected_packages.filter_map do |affected_package|
          next unless version_matches?(affected_package)

          advisory = affected_package.advisory
          {
            id: canonical_identifier(advisory),
            severity: severity_for(advisory)
          }
        end
      end

      private

      attr_reader :name, :purl_type, :version

      def affected_packages
        component = Hashie::Mash.new(name: name, purl_type: purl_type)
        ::PackageMetadata::AffectedPackage.for_occurrences([component]).with_advisory
      end

      def version_matches?(affected_package)
        return true if version.blank?

        matcher = build_matcher(purl_type: affected_package.purl_type, range: affected_package.affected_range)
        matcher.affected?(version)
      rescue SemverDialects::Error
        false
      end

      def canonical_identifier(advisory)
        identifiers = advisory.identifiers
        cve = identifiers.find { |i| i['type'].to_s == 'cve' }
        (cve || identifiers.first)['name']
      end

      def severity_for(advisory)
        vector = [advisory.cvss_v4, advisory.cvss_v3, advisory.cvss_v2].compact.find(&:valid?)
        return UNKNOWN_SEVERITY unless vector

        vector.severity.to_s.downcase
      end
    end
  end
end
