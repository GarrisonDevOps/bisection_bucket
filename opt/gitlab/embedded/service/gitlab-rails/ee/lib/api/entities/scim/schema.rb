# frozen_string_literal: true

module API
  module Entities
    module Scim
      class Schema < Grape::Entity
        expose :schemas, documentation: {
          type: 'Array', example: ['urn:ietf:params:scim:schemas:core:2.0:Schema']
        }
        expose :id, documentation: { type: 'String', example: 'urn:ietf:params:scim:schemas:core:2.0:User' }
        expose :name, documentation: { type: 'String', example: 'User' }
        expose :description, documentation: { type: 'String', example: 'User Account' }
        expose :attributes, documentation: {
          type: 'Array', example: [{ name: 'userName', type: 'string' }]
        }
        expose :meta, documentation: { type: 'Hash' } do
          expose :resource_type, as: :resourceType, documentation: { type: 'String', example: 'Schema' }
          expose :location, documentation: {
            type: 'String',
            example: 'https://gitlab.example.com/api/scim/v2/application/Schemas/urn:ietf:params:scim:schemas:core:2.0:User'
          }
        end

        private

        def schemas
          ['urn:ietf:params:scim:schemas:core:2.0:Schema']
        end

        def resource_type
          'Schema'
        end

        def location
          "#{options[:base_url]}/Schemas/#{object[:id]}"
        end
      end
    end
  end
end
