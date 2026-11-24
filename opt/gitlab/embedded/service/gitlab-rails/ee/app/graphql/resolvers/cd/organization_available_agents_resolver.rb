# frozen_string_literal: true

module Resolvers
  module Cd
    class OrganizationAvailableAgentsResolver < BaseResolver
      type ::Types::Clusters::AgentType.connection_type, null: true

      def resolve
        return unless Feature.enabled?(:ai_native_deploy, current_user)
        return unless Ability.allowed?(current_user, :read_cd_environment, object)

        ::Clusters::Agent.for_organizations([object.id]).ordered_by_name
      end
    end
  end
end
