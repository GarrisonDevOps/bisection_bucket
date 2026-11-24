# frozen_string_literal: true

module Ai
  module ActiveContext
    module Tasks
      class NullifyField < ::ActiveContext::Task[1.0]
        include Concerns::CollectionLookup

        batched!

        DEFAULT_BATCH_SIZE = 10_000

        def required_params
          %w[collection field]
        end

        def execute!
          nullify_field(collection_name, field_name, batch_size: batch_size)
        end

        def completed?
          !any_documents_with_field?
        end

        private

        def any_documents_with_field?
          query = ::ActiveContext::Query.exists(field_name).limit(1)
          collection_class.search(user: nil, query: query).any?
        end

        def field_name
          params['field']
        end

        def batch_size
          params.fetch('batch_size', DEFAULT_BATCH_SIZE).to_i
        end
      end
    end
  end
end
