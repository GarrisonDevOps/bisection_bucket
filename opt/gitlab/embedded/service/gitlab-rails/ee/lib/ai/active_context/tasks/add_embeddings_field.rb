# frozen_string_literal: true

module Ai
  module ActiveContext
    module Tasks
      class AddEmbeddingsField < ::ActiveContext::Task[1.0]
        include Concerns::CollectionLookup

        def required_params
          %w[collection field dimensions]
        end

        def execute!
          add_field(collection_name) { |c| c.vector field_name, dimensions: dimensions }
        end

        private

        def field_name
          params['field']
        end

        def dimensions
          params['dimensions']
        end
      end
    end
  end
end
