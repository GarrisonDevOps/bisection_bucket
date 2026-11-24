# frozen_string_literal: true

module API
  module Entities
    module Admin
      class Model < Grape::Entity
        include ::API::Helpers::RelatedResourcesHelpers

        # rubocop:disable API/EntityFieldType -- Integer for single-column primary keys, Base64-encoded String for composite keys
        expose :record_identifier, documentation: { type: %w[string integer], example: 'abc123' } do |model|
          model.class.primary_key.is_a?(Array) ? expose_composite_key(model) : model.id
        end
        # rubocop:enable API/EntityFieldType
        expose :model_class, documentation: { type: 'String', example: 'Project' } do |model|
          model.class.name
        end
        expose :created_at, documentation: { type: 'DateTime', example: "2025-01-31T15:10:45.080Z" } do |model|
          model.respond_to?(:created_at) ? model.created_at : nil
        end

        # File-specific fields
        expose :file_size, documentation: { type: 'Integer', example: 123 } do |model|
          model.attributes.has_key?('size') ? model.size : nil
        end

        # Geo-specific fields
        expose :checksum_information,
          documentation: { type: "JSON", example: {
            checksum: { type: "string", example: 'abc' },
            last_checksum: { type: "dateTime", example: "2025-01-31T15:10:45.080Z" },
            checksum_state: { type: "string", example: 'pending' },
            checksum_retry_count: { type: "integer", example: 100 },
            checksum_retry_at: { type: "dateTime", example: "2025-01-31T15:10:45.080Z" },
            checksum_failure: { type: "string", example: 'failed' }
          } },
          if: ->(model) { verification_enabled?(model) } do
          expose :verification_checksum, as: :checksum, documentation: { type: 'String' }
          expose :verified_at, as: :last_checksum, documentation: { type: 'DateTime' }
          expose :verification_state_name_no_prefix, as: :checksum_state, documentation: { type: 'String' }
          expose :verification_retry_count, as: :checksum_retry_count, documentation: { type: 'Integer' }
          expose :verification_retry_at, as: :checksum_retry_at, documentation: { type: 'DateTime' }
          expose :verification_failure, as: :checksum_failure, documentation: { type: 'String' }
        end

        private

        def verification_enabled?(model)
          return false unless ::Gitlab::Geo.enabled?
          return false unless model.respond_to?(:replicator)

          model.replicator.class.verification_enabled?
        end

        def expose_composite_key(model)
          array_of_values = model.class.primary_key.map { |field| model.read_attribute_before_type_cast(field) }
          Base64.urlsafe_encode64(array_of_values.join(' '))
        end
      end
    end
  end
end
