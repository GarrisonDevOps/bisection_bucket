# frozen_string_literal: true

module Resolvers
  module Cd
    class OrganizationRolloutResolver < BaseResolver
      type ::Types::Cd::RolloutType, null: true

      argument :id, ::Types::GlobalIDType[::Cd::Rollout],
        required: true,
        description: 'Global ID of the rollout.'

      def resolve(id:)
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        ::Cd::Rollout.in_organization(object).find_by_id(id.model_id)
      end
    end
  end
end
