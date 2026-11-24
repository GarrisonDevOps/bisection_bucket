# frozen_string_literal: true

module API
  module Entities
    module Scim
      class ServiceProviderConfig < Grape::Entity
        expose :schemas, documentation: {
          type: 'Array', example: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig']
        }
        expose :documentationUri, documentation: {
          type: 'String', example: 'https://gitlab.example.com/help/user/group/saml_sso/scim_setup.md'
        }
        expose :patch, documentation: { type: 'Hash', example: { supported: true } }
        expose :bulk, documentation: {
          type: 'Hash', example: { supported: false, maxOperations: 0, maxPayloadSize: 0 }
        }
        expose :filter, documentation: { type: 'Hash', example: { supported: true, maxResults: 100 } }
        expose :changePassword, documentation: { type: 'Hash', example: { supported: false } }
        expose :sort, documentation: { type: 'Hash', example: { supported: false } }
        expose :etag, documentation: { type: 'Hash', example: { supported: false } }
        expose :authenticationSchemes, documentation: {
          type: 'Array', example: [{ type: 'oauthbearertoken', name: 'OAuth Bearer Token', primary: true }]
        }

        expose :meta, documentation: { type: 'Hash' } do
          expose :resource_type, as: :resourceType, documentation: { type: 'String', example: 'ServiceProviderConfig' }
          expose :location, documentation: {
            type: 'String', example: 'https://gitlab.example.com/api/scim/v2/application/ServiceProviderConfig'
          }
        end

        private

        def resource_type
          'ServiceProviderConfig'
        end

        def location
          "#{options[:base_url]}/ServiceProviderConfig"
        end
      end
    end
  end
end
