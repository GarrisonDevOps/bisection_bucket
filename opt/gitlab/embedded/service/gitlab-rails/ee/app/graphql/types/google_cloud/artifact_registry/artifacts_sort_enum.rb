# frozen_string_literal: true

module Types
  module GoogleCloud
    module ArtifactRegistry
      class ArtifactsSortEnum < BaseEnum
        graphql_name 'GoogleCloudArtifactRegistryArtifactsSort'
        description 'Values for sorting artifacts'

        FIELDS = %i[name image_size_bytes upload_time build_time update_time media_type].freeze
        DIRECTIONS = %i[asc desc].freeze

        FIELDS.each do |field|
          DIRECTIONS.each do |direction|
            value "#{field}_#{direction}".upcase,
              description: "Ordered by `#{field}` in #{direction}ending order.",
              value: "#{field} #{direction}"
          end
        end
      end
    end
  end
end
