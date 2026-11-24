# frozen_string_literal: true

module Sbom
  module Ingestion
    module Tasks
      class IngestComponentVersions < Base
        # The org-scoped unique index is added by a post-deployment migration, which
        # runs *after* the new code is already serving traffic. Until it exists we must
        # keep upserting against the legacy `[component_id, version]` index, otherwise
        # the bulk upsert fails with "No unique index found".
        NEW_UNIQUE_INDEX_NAME = 'idx_sbom_comp_versions_on_comp_id_version_and_org_id'
        NEW_UNIQUE_BY = %i[component_id version organization_id].freeze
        LEGACY_UNIQUE_BY = %i[component_id version].freeze

        self.model = Sbom::ComponentVersion
        self.uses = %i[id component_id version organization_id].freeze

        private

        def unique_by
          new_unique_index_available? ? NEW_UNIQUE_BY : LEGACY_UNIQUE_BY
        end
        strong_memoize_attr :unique_by

        def new_unique_index_available?
          model.connection.index_name_exists?(model.table_name, NEW_UNIQUE_INDEX_NAME)
        end
        strong_memoize_attr :new_unique_index_available?

        def existing_records
          @existing_records ||= occurrence_maps.map do |occurrence_map|
            Sbom::ComponentVersion.by_component_id_and_version(*occurrence_map.to_h.values_at(:component_id, :version))
          end.reduce(:or)
        end

        def existing_record(map_data)
          existing_records.find do |version|
            unique_by.all? do |attribute|
              map_data[attribute] == version[attribute]
            end
          end
        end

        def after_ingest
          each_pair do |occurrence_map, row|
            occurrence_map.component_version_id = row.first
          end
        end

        def attributes
          insertable_maps.filter_map do |occurrence_map|
            map_data = occurrence_map.to_h.slice(:component_id, :version).merge!(organization_id: organization_id)
            existing_record = existing_record(map_data)

            if existing_record.present?
              occurrence_map.component_version_id = existing_record.id
              next
            end

            map_data
          end
        end

        # `OccurrenceMap#to_h` does not carry `organization_id`, so the default grouping
        # key (built from `to_h`) cannot align map rows with returned DB rows when the
        # org-scoped `unique_by` is active. Build the key explicitly from `unique_by`.
        def grouping_key_for_map(map)
          map_data = map.to_h
          unique_by.map do |attribute|
            attribute == :organization_id ? organization_id : map_data[attribute]
          end
        end

        def insertable_maps
          super.filter(&:version_present?)
        end
      end
    end
  end
end
