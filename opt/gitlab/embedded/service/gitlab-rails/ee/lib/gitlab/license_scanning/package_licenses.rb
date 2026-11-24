# frozen_string_literal: true

module Gitlab
  module LicenseScanning
    class PackageLicenses
      include Gitlab::InternalEventsTracking
      include Gitlab::Utils::StrongMemoize

      BATCH_SIZE = 700
      UNKNOWN_LICENSE = {
        spdx_identifier: "unknown",
        name: "unknown",
        url: nil
      }.freeze

      def initialize(components:, project: nil)
        @components = components
        # component_data keeps track of the requested versions for each component, to
        # facilitate faster lookups by avoiding an O(n^2) search against the components array
        @component_data = Hash.new { |h, k| h[k] = [] }
        @all_records = {}
        @project = project

        # collect PURL types and initialize counters for event tracking
        @purl_types = components.map(&:purl_type).uniq
        @count_of_components = @purl_types.index_with do
          {
            all: 0,
            with_licenses_from_sbom: 0,
            with_scan_results: 0,
            without_scan_results: 0
          }
        end
      end

      def self.url_for(spdx_id)
        return if spdx_id.blank? || spdx_id == "unknown"

        "https://spdx.org/licenses/#{spdx_id}.html"
      end

      # obtains licenses by using data from the `licenses` jsonb column in the pm_packages table to query
      # data from the pm_licenses table
      def fetch
        ::Gitlab::Database::LoadBalancing::SessionMap.use_replica_if_available do
          init_all_records_to_unknown_licenses do |component|
            # build cache for faster lookups of licenses and component_version data
            build_component_data_cache(component)
          end

          # For each batch of components, we execute two queries for components without license:
          #
          # 1. Retrieve the packages for the components by querying the pm_packages table
          # 2. Use the data in the `licenses` jsonb column of the pm_packages table to
          #    lookup the corresponding licenses. This query is executed by the
          #    `package.licenses_for` method.
          components.each_slice(BATCH_SIZE).each do |components_batch|
            components_with_licenses, components_without_licenses = components_batch.partition do |c|
              license_configuration_source_sbom? && c.licenses.present?
            end

            add_components_with_license(components_with_licenses)
            add_components_without_licenses(components_without_licenses)
          end

          track_events

          all_records.values
        end
      end

      private

      attr_reader :components, :component_data, :all_records, :project

      # set the default license of all components to an unknown license,
      # and increment the count of components with unknown licenses.
      # If a license is eventually found for the component, we'll overwrite
      # the unknown entry with the valid license, decrement the count
      # of components with unknown licenses, and increment the count of
      # components with known licenses.
      # Initializing all records with an unknown license allows us to ensure
      # that the packages and licenses we return from the fetch method are the
      # same order as the components that were initially passed to the fetch
      # method. This allows callers to make assumptions about the ordering of
      # the data, which can simplify their code.
      def init_all_records_to_unknown_licenses
        components.each do |component|
          add_record_with_unknown_license(component)

          yield component if block_given?

          counts = @count_of_components[component.purl_type]
          counts[:all] += 1
          counts[:without_scan_results] += 1
        end
      end

      def add_record_with_unknown_license(component)
        key = component_key(name: component.name, version: component.version, purl_type: component.purl_type)

        all_records[key] =
          Hashie::Mash.new(
            purl_type: component.purl_type, name: component.name, version: component.version,
            licenses: [UNKNOWN_LICENSE], path: component.path || ''
          )
      end

      def component_key(name:, version:, purl_type:)
        "#{name}/#{version}/#{purl_type}"
      end

      # we fetch package details from the pm_packages table which only contains the
      # purl_type and name. We need a way to know which versions were requested for
      # each purl_type and name, so we use a hash to store this data for faster lookups.
      def build_component_data_cache(component)
        component_data[component_data_key(name: component.name, purl_type: component.purl_type)] <<
          { version: component.version, path: component.path }
      end

      def component_data_key(name:, purl_type:)
        "#{name}/#{purl_type}"
      end

      def add_components_without_licenses(components_without_licenses)
        packages_for_batch = ::PackageMetadata::Package.packages_for(components: components_without_licenses)

        packages_for_batch.each do |package|
          requested_data_for_package(package).each do |component|
            license_ids = license_ids_for(package, component[:version])

            next if license_ids.empty?

            add_record_with_known_licenses(purl_type: package.purl_type, name: package.name,
              version: component[:version], license_ids: license_ids, path: component[:path])

            counts = @count_of_components[package.purl_type]
            counts[:with_scan_results] += 1
            counts[:without_scan_results] -= 1
          end
        end
      end

      def license_ids_for(package, version)
        strong_memoize_with(:license_ids_for, package, version) do
          package.license_ids_for(version: version)
        end
      end

      def requested_data_for_package(package)
        component_data[component_data_key(name: package.name, purl_type: package.purl_type)]
      end

      # Every time a license is encountered for a component, we record it.
      # This allows us to determine which components do not have licenses.
      # Adds a single record with known licenses. This method is used by both the
      # uncompressed and compressed queries.
      def add_record_with_known_licenses(purl_type:, name:, version:, license_ids:, path:)
        all_records[component_key(name: name, version: version, purl_type: purl_type)] =
          Hashie::Mash.new(
            purl_type: purl_type, name: name, version: version,
            licenses: licenses_with_names_for(license_ids: license_ids), path: path || ''
          )
      end

      def licenses_with_names_for(license_ids:)
        return [UNKNOWN_LICENSE] if license_ids.blank?

        expression_values = license_ids.filter_map { |id| expressions[id] }

        if expression_values.any?
          expression_values.map { |value| expression_hash_for(value) }
        else
          license_ids.map { |id| license_hash_for(identifiers[id]) }
        end
      end

      def license_hash_for(value)
        {
          spdx_identifier: value,
          name: license_name_for(spdx_id: value),
          url: self.class.url_for(value)
        }
      end

      def expression_hash_for(value)
        {
          spdx_identifier: nil,
          name: value,
          url: nil,
          expression: value
        }
      end

      # pm_licenses is small and rarely changes, so we cache the full-table load to avoid repeated sql queries.
      def identifiers
        build_license_maps if @identifiers.nil?
        @identifiers
      end

      def expressions
        build_license_maps if @expressions.nil?
        @expressions
      end

      def build_license_maps
        @identifiers = {}
        @expressions = {}

        ::PackageMetadata::License.select_id_and_spdx_values.each_batch(of: 500) do |batch|
          batch.each do |license|
            if license.spdx_expression.present?
              @expressions[license.id] = license.spdx_expression
            else
              @identifiers[license.id] = license.spdx_identifier
            end
          end
        end
      end

      # there's only about 650 _valid_ licenses in the software_licenses table, and the data doesn't change often,
      # so we use a cache to avoid a separate sql query every time we need to convert from spdx_identifier to
      # license name.
      def license_name_for(spdx_id:)
        catalogue_licenses_map[spdx_id] || spdx_id
      end

      def catalogue_licenses_map
        Gitlab::SPDX::Catalogue.latest_active_licenses.to_h do |license|
          [license.id, license.name]
        end
      end
      strong_memoize_attr :catalogue_licenses_map

      def add_components_with_license(components_with_licenses)
        components_with_licenses.each do |component|
          add_record_with_ingested_licenses(component) if supported_for_license_scanning?(component.purl_type)

          counts = @count_of_components[component.purl_type]
          counts[:with_licenses_from_sbom] += 1
          counts[:without_scan_results] -= 1
        end
      end

      def add_record_with_ingested_licenses(component)
        all_records[component_key(name: component.name, version: component.version,
          purl_type: component.purl_type)] = Hashie::Mash.new(
            purl_type: component.purl_type, name: component.name, version: component.version,
            licenses: licenses_for_component(component), path: component.path || ''
          )
      end

      def licenses_for_component(component)
        licenses = component.licenses.to_a.map do |component_license|
          spdx_id = component_license.spdx_identifier

          license = {
            spdx_identifier: spdx_id,
            name: component_license.name || license_name_for(spdx_id: spdx_id),
            url: component_license.url || self.class.url_for(spdx_id)
          }
          license[:expression] = component_license.expression if component_license.expression.present?
          license
        end

        # A component that declares a license is always resolved from the SBOM, never PMDB.
        # `fetch` only routes components with licenses here, so this fallback is defensive:
        # an empty list would break Reports::LicenseScanning::Report#licenses.
        licenses.presence || [UNKNOWN_LICENSE]
      end

      def supported_for_license_scanning?(purl_type)
        ::Enums::Sbom.dependency_scanning_purl_type?(purl_type) ||
          ::Enums::Sbom.container_scanning_purl_type?(purl_type)
      end

      def track_events
        @purl_types.each do |purl_type|
          counts = @count_of_components[purl_type]

          additional_properties = {
            label: purl_type,
            property: scan_type_for_purl_type(purl_type),
            value: counts[:all],
            components_with_licenses_from_sbom: counts[:with_licenses_from_sbom],
            components_with_scan_results: counts[:with_scan_results],
            components_without_scan_results: counts[:without_scan_results]
          }

          track_internal_event(
            'license_scanning_scan',
            project: project,
            additional_properties: additional_properties
          )
        end
      end

      def scan_type_for_purl_type(purl_type)
        case purl_type
        when *Enums::Sbom::CONTAINER_SCANNING_PURL_TYPES
          'container_scanning'
        when *Enums::Sbom::DEPENDENCY_SCANNING_PURL_TYPES
          'dependency_scanning'
        else
          'unknown'
        end
      end

      def license_configuration_source_sbom?
        return true unless project

        project.security_setting&.sbom_license_configuration_source?
      end
      strong_memoize_attr :license_configuration_source_sbom?
    end
  end
end
