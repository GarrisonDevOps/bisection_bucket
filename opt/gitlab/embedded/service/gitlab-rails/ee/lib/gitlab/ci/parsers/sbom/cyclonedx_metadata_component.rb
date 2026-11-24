# frozen_string_literal: true

module Gitlab
  module Ci
    module Parsers
      module Sbom
        class CyclonedxMetadataComponent
          REQUIRED_PROPERTIES = %w[
            name
            type
            bom-ref
          ].freeze

          FILE_PROPERTY_PREFIX = 'gitlab:dependency_scanning:file:'
          FILE_COMPONENT_TYPE = 'file'
          VALID_FILE_TYPES = %w[requirements lockfile graphfile].freeze

          def initialize(properties)
            @properties = properties
          end

          def parse_component
            return if missing_properties.present?

            ::Gitlab::Ci::Reports::Sbom::Component.new(
              ref: properties['bom-ref'],
              type: properties['type'],
              name: properties['name'],
              purl: nil,
              version: nil
            )
          end

          def parse_files
            return [] unless properties.present?

            Array.wrap(properties['components']).filter_map do |comp|
              next unless comp['type'] == FILE_COMPONENT_TYPE && comp['name'].present?

              file_props = parse_file_properties(comp['properties'])

              next unless VALID_FILE_TYPES.include?(file_props['type'])

              {
                'path' => comp['name'],
                'type' => file_props['type'],
                'in_repository' => (file_props['in_repository'].to_s == 'true' if file_props.key?('in_repository'))
              }.compact
            end
          end

          private

          attr_reader :properties

          def missing_properties
            REQUIRED_PROPERTIES - properties&.keys.to_a
          end

          def parse_file_properties(raw_properties)
            Array.wrap(raw_properties).each_with_object({}) do |prop, hash|
              name = prop['name']
              value = prop['value']
              next unless name&.start_with?(FILE_PROPERTY_PREFIX)

              key = name.delete_prefix(FILE_PROPERTY_PREFIX)
              hash[key] = value
            end
          end
        end
      end
    end
  end
end
