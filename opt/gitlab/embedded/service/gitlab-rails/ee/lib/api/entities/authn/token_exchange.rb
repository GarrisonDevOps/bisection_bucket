# frozen_string_literal: true

module API
  module Entities
    module Authn
      class TokenExchange < Grape::Entity
        expose :access_token, documentation: { type: 'String', example: 'eyJhbGciOiJSUzI1NiJ9...' }
        expose :issued_token_type,
          documentation: { type: 'String', example: 'urn:ietf:params:oauth:token-type:jwt' }
        expose :token_type, documentation: { type: 'String', example: 'Bearer' }
        expose :expires_in, documentation: { type: 'Integer', example: 300 }
        expose :token,
          documentation: { type: 'String', example: 'eyJhbGciOiJSUzI1NiJ9...',
                           desc: "Same value as access_token, for clients that read token, " \
                             "such as Docker's registry token auth flow." }
      end
    end
  end
end
