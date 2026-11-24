# frozen_string_literal: true

module Resolvers
  module SecretsManagement
    class OpenbaoHealthResolver < BaseResolver
      type GraphQL::Types::Boolean, null: false
      include ::SecretsManagement::ResolverErrorHandling

      description 'Check if OpenBao instance is healthy and reachable'

      TIMEOUT_SECONDS = 5.0

      def resolve
        raise_resource_not_available_error! unless current_user

        # we don't need JWT here since the health endpoint from Openbao is public
        client = ::SecretsManagement::SecretsManagerClient.new(jwt: nil, timeout: TIMEOUT_SECONDS)
        client.server_available?
      end
    end
  end
end
