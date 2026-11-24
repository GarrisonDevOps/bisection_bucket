# frozen_string_literal: true

module Ai
  module ActiveContext
    module Tasks
      class UpdateCollectionMetadata < ::ActiveContext::Task[1.0]
        include Concerns::CollectionLookup

        def required_params
          %w[collection metadata]
        end

        def execute!
          raise TaskError, "Collection '#{collection_name}' not found" unless collection_record

          collection_record.update_metadata!(metadata)
        end

        private

        def collection_record
          @collection_record ||=
            ::Ai::ActiveContext::Collection.find_by_name(connection, full_collection_name(collection_name))
        end

        def metadata
          params['metadata']
        end
      end
    end
  end
end
