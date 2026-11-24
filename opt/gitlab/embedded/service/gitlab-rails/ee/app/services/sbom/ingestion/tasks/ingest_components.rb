# frozen_string_literal: true

module Sbom
  module Ingestion
    module Tasks
      class IngestComponents < Base
        COMPONENT_ATTRIBUTES = %i[name purl_type component_type organization_id].freeze

        self.model = Sbom::Component
        self.unique_by = COMPONENT_ATTRIBUTES
        self.uses = %i[id name purl_type component_type organization_id].freeze

        private

        def existing_records
          @existing_records ||= occurrence_maps.map do |occurrence_map|
            name, purl_type, component_type = occurrence_map.to_h.values_at(:name, :purl_type, :component_type)

            Sbom::Component.by_unique_attributes(name, purl_type, component_type, organization_id)
          end.reduce(:or)
        end

        def existing_record(map_data)
          existing_records.find do |component|
            COMPONENT_ATTRIBUTES.all? { |attribute| map_data[attribute] == component[attribute] }
          end
        end

        def after_ingest
          each_pair do |occurrence_map, row|
            occurrence_map.component_id = row.first
          end
        end

        def attributes
          insertable_maps.filter_map do |occurrence_map|
            map_data = occurrence_map.to_h.slice(*COMPONENT_ATTRIBUTES).merge!(organization_id: organization_id)
            existing_record = existing_record(map_data)

            if existing_record.present?
              occurrence_map.component_id = existing_record.id
              next
            end

            map_data
          end
        end

        def grouping_key_for_map(map)
          [map.name, map.purl_type, map.report_component.component_type, organization_id]
        end
      end
    end
  end
end
