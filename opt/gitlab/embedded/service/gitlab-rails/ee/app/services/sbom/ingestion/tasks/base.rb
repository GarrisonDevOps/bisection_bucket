# frozen_string_literal: true

module Sbom
  module Ingestion
    module Tasks
      class Base
        include Gitlab::Utils::StrongMemoize
        include Gitlab::Ingestion::BulkInsertableTask
        extend ::Gitlab::Utils::Override

        def self.execute(pipeline, occurrence_maps)
          new(pipeline, occurrence_maps).execute
        end

        def initialize(pipeline, occurrence_maps)
          @pipeline = pipeline
          @occurrence_maps = occurrence_maps
        end

        private

        attr_reader :pipeline, :occurrence_maps

        delegate :project, to: :pipeline, private: true

        # Override bulk operations to disable ActiveRecord validations for performance.
        # We perform manual validation filtering in #filter_invalid_objects before
        # bulk operations to ensure only valid objects reach the database while
        # avoiding redundant validation passes during bulk insert/upsert.
        override :bulk_insert
        def bulk_insert
          klass.bulk_insert!(insert_objects, skip_duplicates: true, returns: uses, validate: false)
        end

        override :bulk_upsert
        def bulk_upsert
          klass.bulk_upsert!(insert_objects, unique_by: unique_by, returns: uses, validate: false) do |attr|
            slice_attributes(attr)
          end
        end

        override :insert_objects
        def insert_objects
          filter_invalid_objects(super)
        end

        def filter_invalid_objects(objects)
          valid_objects, invalid_objects = objects.partition(&:valid?)
          log_invalid_objects(invalid_objects) if invalid_objects.any?

          valid_objects
        end

        def log_invalid_objects(invalid_objects)
          errors = invalid_objects.flat_map do |obj|
            obj.errors.map do |error|
              {
                model: obj.class.name,
                error: error.full_message,
                attribute_name: error.attribute.to_s,
                attribute_value: obj[error.attribute]
              }
            end
          end.uniq

          ::Gitlab::AppLogger.warn(
            message: "Components failed validation during SBoM ingestion",
            project_id: project.id,
            errors: errors
          )
        end

        def organization_id
          project.namespace.organization_id
        end

        def insertable_maps
          occurrence_maps
        end

        def each_pair
          validate_unique_by!

          return_data.each do |row|
            occurrence_maps_for_row(row).each { |map| yield map, row }
          end
        end

        def occurrence_maps_for_row(row)
          indexed_occurrence_maps[grouping_key_for_row(row)]
        end

        def indexed_occurrence_maps
          insertable_maps.group_by { |map| grouping_key_for_map(map) }
        end
        strong_memoize_attr :indexed_occurrence_maps

        def grouping_key_for_map(occurrence_map)
          occurrence_map.to_h.values_at(*unique_by)
        end

        def unique_attr_indices
          unique_by.map { |attr| uses.find_index(attr) }
        end
        strong_memoize_attr :unique_attr_indices

        def grouping_key_for_row(row)
          unique_attr_indices.map { |index| row[index] }
        end

        def validate_unique_by!
          raise ArgumentError, '#each_pair can only be used with unique_by attributes' if unique_by.blank?

          return if unique_by.all? { |attr| uses.include?(attr) }

          raise ArgumentError, 'All unique_by attributes must be included in returned columns'
        end
      end
    end
  end
end
