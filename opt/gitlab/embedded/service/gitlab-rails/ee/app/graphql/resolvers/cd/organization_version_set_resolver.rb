# frozen_string_literal: true

module Resolvers
  module Cd
    class OrganizationVersionSetResolver < BaseResolver
      type ::Types::Cd::VersionSetType, null: true

      argument :id, ::Types::GlobalIDType[::Cd::VersionSet],
        required: true,
        description: 'Global ID of the version set.'

      def resolve(id:)
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        ::Cd::VersionSet.in_organization(object).find_by_id(id.model_id)
      end
    end
  end
end
