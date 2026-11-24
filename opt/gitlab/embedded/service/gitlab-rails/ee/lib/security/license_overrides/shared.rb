# frozen_string_literal: true

module Security
  module LicenseOverrides
    module Shared
      MODES = { patch: 'patch', overwrite: 'overwrite' }.freeze

      # SPDX catalog is loaded from a static file bundled with the app.
      # Module-level memoization is intentional: the catalog only changes on redeployment,
      # and a single copy is shared across all including classes.
      def self.spdx_catalog_map
        @spdx_catalog_map ||= begin
          licenses = Gitlab::SPDX::Catalogue.latest_active_licenses
          { by_id: licenses.index_by(&:id), by_name: licenses.index_by { |l| l.name.downcase } }
        end
      end

      private

      def purl_matches?(dependency_purl, override_purl)
        dep = Sbom::PackageUrl.parse(dependency_purl)
        ov = parsed_override_purl_cache[override_purl]
        return false unless ov

        base_match = dep.type == ov.type && dep.namespace == ov.namespace && dep.name == ov.name
        return base_match if ov.version.nil?

        base_match && dep.version == ov.version
      rescue Sbom::PackageUrl::InvalidPackageUrl
        false
      end

      def parsed_override_purl_cache
        @parsed_override_purl_cache ||= active_overrides.each_with_object({}) do |override, cache|
          purl = override['purl']
          next if purl.blank?

          cache[purl] = Sbom::PackageUrl.parse(purl)
        rescue Sbom::PackageUrl::InvalidPackageUrl
          nil
        end
      end

      # Resolves a user-provided license string to a (spdx_id, display_name, url) triple.
      # The user may provide either:
      #   - An SPDX ID (e.g., "MIT") -> returns ("MIT", "MIT License", "https://spdx.org/licenses/MIT.html")
      #   - A display name (e.g., "MIT License") -> returns ("MIT", "MIT License", "https://...")
      #   - A custom identifier (e.g., "LicenseRef-Acme") -> returns ("LicenseRef-Acme", "LicenseRef-Acme", nil)
      def resolve_license_identity(license_string)
        spdx_license = spdx_catalog_map[:by_id][license_string]
        return [spdx_license.id, spdx_license.name, spdx_license.url] if spdx_license

        spdx_license = spdx_catalog_map[:by_name][license_string.downcase]
        return [spdx_license.id, spdx_license.name, spdx_license.url] if spdx_license

        [license_string, license_string, nil]
      end

      def spdx_catalog_map
        Shared.spdx_catalog_map
      end
    end
  end
end
