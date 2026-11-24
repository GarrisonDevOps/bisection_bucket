# frozen_string_literal: true

module Security
  module DependencyFirewall
    class FetchPackageLicensesService
      def initialize(name:, purl_type:, version:)
        @name = name
        @purl_type = purl_type
        @version = version
      end

      def execute
        fetch_licenses
      end

      private

      attr_reader :name, :purl_type, :version

      def fetch_licenses
        component = Hashie::Mash.new(name: name, purl_type: purl_type, version: version, path: nil)

        ::Gitlab::LicenseScanning::PackageLicenses
          .new(components: [component], project: nil)
          .fetch
          .flat_map { |result| result.fetch(:licenses, []) }
          .filter_map { |license| map_license(license) }
      end

      def map_license(license)
        spdx_identifier = license[:spdx_identifier]

        return if spdx_identifier.blank?
        return if spdx_identifier == ::Gitlab::LicenseScanning::PackageLicenses::UNKNOWN_LICENSE[:spdx_identifier]

        { spdx_identifier: spdx_identifier, name: license[:name], url: license[:url] }
      end
    end
  end
end
