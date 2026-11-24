# frozen_string_literal: true

module API
  module Entities
    module Scim
      class ResourceTypes < Grape::Entity
        expose :schemas, documentation: {
          type: 'Array', example: ['urn:ietf:params:scim:api:messages:2.0:ListResponse']
        }
        expose :total_results, as: :totalResults, documentation: { type: 'Integer', example: 2 }
        expose :items_per_page, as: :itemsPerPage, documentation: { type: 'Integer', example: 2 }
        expose :start_index, as: :startIndex, documentation: { type: 'Integer', example: 1 }

        expose :resources, as: :Resources, using: ::API::Entities::Scim::ResourceType, documentation: { is_array: true }

        private

        DEFAULT_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse'

        def schemas
          [DEFAULT_SCHEMA]
        end

        def total_results
          resources.size
        end

        def items_per_page
          resources.size
        end

        def start_index
          1
        end

        def resources
          object[:resources] || []
        end
      end
    end
  end
end
