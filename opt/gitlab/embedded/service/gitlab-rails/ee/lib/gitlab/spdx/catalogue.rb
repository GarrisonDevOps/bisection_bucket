# frozen_string_literal: true

module Gitlab
  module SPDX
    class Catalogue
      include Enumerable

      LATEST_LICENSES_CACHE_KEY = [name, 'latest_licenses'].freeze
      LATEST_ACTIVE_LICENSES_CACHE_KEY = [name, 'latest_active_licenses'].freeze

      def initialize(catalogue = {})
        @catalogue = catalogue
      end

      def version
        catalogue[:licenseListVersion]
      end

      def each
        licenses.each do |license|
          yield license
        end
      end

      def self.latest
        CatalogueGateway.new.fetch
      end

      def licenses
        @licenses ||= catalogue.fetch(:licenses, []).map { |x| map_from(x) }
      end

      def self.latest_licenses
        Rails.cache.fetch(LATEST_LICENSES_CACHE_KEY, expires_in: 7.days) do
          (latest.licenses + [::Gitlab::SPDX::License.unknown]).sort_by(&:name)
        end
      end

      def self.latest_active_licenses
        Rails.cache.fetch(LATEST_ACTIVE_LICENSES_CACHE_KEY, expires_in: 7.days) do
          latest.licenses.reject(&:deprecated).sort_by(&:name)
        end
      end

      def self.latest_active_license_names
        latest_active_licenses.map(&:name)
      end

      private

      attr_reader :catalogue

      def map_from(license_hash)
        ::Gitlab::SPDX::License.new(
          id: license_hash[:licenseId],
          name: license_hash[:name],
          deprecated: license_hash[:isDeprecatedLicenseId]
        )
      end
    end
  end
end
