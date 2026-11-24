# frozen_string_literal: true

module API
  module Entities
    module Scim
      class Users < Grape::Entity
        expose :schemas, documentation: { type: 'String', is_array: true }
        expose :total_results, as: :totalResults, documentation: { type: 'Integer' }
        expose :items_per_page, as: :itemsPerPage, documentation: { type: 'Integer' }
        expose :start_index, as: :startIndex, documentation: { type: 'Integer' }

        expose :resources, as: :Resources, using: ::API::Entities::Scim::User, documentation: { is_array: true }

        private

        DEFAULT_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse'

        def schemas
          [DEFAULT_SCHEMA]
        end

        def total_results
          object[:total_results] || resources.size
        end

        def items_per_page
          object[:items_per_page] || Kaminari.config.default_per_page
        end

        def start_index
          object[:start_index].presence || 1
        end

        def resources
          object[:resources] || []
        end
      end
    end
  end
end
