# frozen_string_literal: true

module Resolvers
  module Cd
    class OrganizationEnvironmentTiersResolver < BaseResolver
      type [::Types::Cd::EnvironmentTierEnum], null: true

      def resolve
        return unless Feature.enabled?(:ai_native_deploy, current_user)
        return unless Ability.allowed?(current_user, :read_cd_environment, object)

        ::Cd::Environment.tiers.keys
      end
    end
  end
end
