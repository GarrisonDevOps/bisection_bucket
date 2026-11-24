# frozen_string_literal: true

module Sbom
  module Ingestion
    module Tasks
      class IngestSourcePackages < Base
        SOURCE_PACKAGE_ATTRIBUTES = %i[name purl_type organization_id].freeze

        self.model = Sbom::SourcePackage
        self.unique_by = SOURCE_PACKAGE_ATTRIBUTES.freeze
        self.uses = ([:id] + SOURCE_PACKAGE_ATTRIBUTES).freeze

        private

        def after_ingest
          each_pair do |occurrence_map, row|
            occurrence_map.source_package_id = row.first
          end
        end

        def attributes
          insertable_maps.map do |occurrence_map|
            {
              name: occurrence_map.source_package_name,
              purl_type: occurrence_map.purl_type,
              organization_id: organization_id
            }
          end
        end

        def insertable_maps
          super.filter(&:source_package_name)
        end

        def grouping_key_for_map(map)
          [map.source_package_name, map.purl_type, organization_id]
        end
      end
    end
  end
end
