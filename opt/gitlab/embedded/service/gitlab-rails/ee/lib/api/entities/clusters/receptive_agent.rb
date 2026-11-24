# frozen_string_literal: true

module API
  module Entities
    module Clusters
      class ReceptiveAgent < Grape::Entity
        expose :agent_id, as: :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
        expose :url, documentation: { type: 'String' }
        expose :ca_cert, documentation: { type: 'String' }
        expose :tls_host, documentation: { type: 'String' }
        expose :jwt, documentation: { type: 'Hash' }
        expose :mtls, documentation: { type: 'Hash' }

        def jwt
          return unless object.private_key

          { private_key: Base64.strict_encode64(object.private_key) }
        end

        def mtls
          return unless object.client_key && object.client_cert

          {
            client_key: object.client_key,
            client_cert: object.client_cert
          }
        end
      end
    end
  end
end
