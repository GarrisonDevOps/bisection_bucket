# frozen_string_literal: true

module API
  module Entities
    module Scim
      class ResourceType < Grape::Entity
        expose :schemas, documentation: {
          type: 'Array', example: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType']
        }
        expose :id, documentation: { type: 'String', example: 'User' }
        expose :name, documentation: { type: 'String', example: 'User' }
        expose :endpoint, documentation: { type: 'String', example: '/Users' }
        expose :description, documentation: { type: 'String', example: 'User Account' }
        expose :schema, documentation: {
          type: 'String', example: 'urn:ietf:params:scim:schemas:core:2.0:User'
        }
        expose :meta, documentation: { type: 'Hash' } do
          expose :resource_type, as: :resourceType, documentation: { type: 'String', example: 'ResourceType' }
          expose :location, documentation: {
            type: 'String', example: 'https://gitlab.example.com/api/scim/v2/application/ResourceTypes/User'
          }
        end

        private

        def resource_type
          'ResourceType'
        end

        def location
          "#{options[:base_url]}/ResourceTypes/#{object[:id]}"
        end
      end
    end
  end
end
