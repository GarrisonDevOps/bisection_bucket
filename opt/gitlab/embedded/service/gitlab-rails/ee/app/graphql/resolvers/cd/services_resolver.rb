# frozen_string_literal: true

module Resolvers
  module Cd
    class ServicesResolver < BaseResolver
      include LooksAhead

      type ::Types::Cd::ServiceType.connection_type, null: true

      alias_method :application, :object

      argument :search, GraphQL::Types::String,
        required: false,
        description: 'Search services by name or description.'

      def resolve_with_lookahead(search: nil, **)
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        services = application.services
        services = services.search(search) if search.present?

        apply_lookahead(services)
      end

      private

      def preloads
        {
          service_environment_healths: [:service_environment_healths]
        }
      end
    end
  end
end
