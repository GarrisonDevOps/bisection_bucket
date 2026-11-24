# frozen_string_literal: true

module Resolvers
  module Cd
    class OrganizationEnvironmentResolver < BaseResolver
      type ::Types::Cd::EnvironmentType, null: true

      argument :id, ::Types::GlobalIDType[::Cd::Environment],
        required: true,
        description: 'Global ID of the environment.'

      def resolve(id:)
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        ::Cd::Environment.in_organization(object).find_by_id(id.model_id)
      end
    end
  end
end
