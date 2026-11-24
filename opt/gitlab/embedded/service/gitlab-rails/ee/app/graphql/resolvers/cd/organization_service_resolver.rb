# frozen_string_literal: true

module Resolvers
  module Cd
    class OrganizationServiceResolver < BaseResolver
      type ::Types::Cd::ServiceType, null: true

      argument :id, ::Types::GlobalIDType[::Cd::Service],
        required: true,
        description: 'Global ID of the service.'

      def resolve(id:)
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        ::Cd::Service.in_organization(object).find_by_id(id.model_id)
      end
    end
  end
end
