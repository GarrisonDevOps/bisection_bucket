# frozen_string_literal: true

module Resolvers
  module Cd
    class OrganizationAvailableDeployDriversResolver < BaseResolver
      type [GraphQL::Types::String], null: true

      def resolve
        return unless Feature.enabled?(:ai_native_deploy, current_user)
        return unless Ability.allowed?(current_user, :read_cd_environment, object)

        ::Cd::DeployDrivers::Registry.driver_refs
      end
    end
  end
end
