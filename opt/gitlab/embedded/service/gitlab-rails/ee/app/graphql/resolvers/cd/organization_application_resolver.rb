# frozen_string_literal: true

module Resolvers
  module Cd
    class OrganizationApplicationResolver < BaseResolver
      type ::Types::Cd::ApplicationType, null: true

      argument :id, ::Types::GlobalIDType[::Cd::Application],
        required: true,
        description: 'Global ID of the application.'

      def resolve(id:)
        return unless Feature.enabled?(:ai_native_deploy, current_user)

        ::Cd::Application.in_organization(object).find_by_id(id.model_id)
      end
    end
  end
end
