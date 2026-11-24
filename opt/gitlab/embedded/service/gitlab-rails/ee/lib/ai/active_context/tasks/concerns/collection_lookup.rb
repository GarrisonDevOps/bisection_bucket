# frozen_string_literal: true

module Ai
  module ActiveContext
    module Tasks
      module Concerns
        module CollectionLookup
          def collection_name
            params['collection']
          end

          def collection_class
            "Ai::ActiveContext::Collections::#{collection_name.classify}".constantize
          end
        end
      end
    end
  end
end
