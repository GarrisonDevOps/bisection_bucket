# frozen_string_literal: true

module API
  module Entities
    class ResourceAccessTokenWithToken < Entities::ResourceAccessToken
      expose :token, documentation: { type: 'String', example: 'glpat-<example-token>' }
    end
  end
end
