# frozen_string_literal: true

module Resolvers
  module Cd
    class OrganizationEnvironmentsResolver < BaseResolver
      type ::Types::Cd::EnvironmentType.connection_type, null: true

      MAX_PAGE_SIZE = 100

      max_page_size MAX_PAGE_SIZE

      argument :tier, ::Types::Cd::EnvironmentTierEnum,
        required: false,
        description: 'Filter environments by tier.'

      argument :search, GraphQL::Types::String,
        required: false,
        description: 'Search environments by name or description.'

      argument :application_id, ::Types::GlobalIDType[::Cd::Application],
        required: false,
        description: 'Filter environments to those where the application has services deployed.'

      argument :status, ::Types::Cd::EnvironmentStatusEnum,
        required: false,
        description: 'Filter environments by status. An environment can match more than one status.'

      def resolve(tier: nil, search: nil, application_id: nil, status: nil)
        return unless Feature.enabled?(:ai_native_deploy, current_user)
        return unless Ability.allowed?(current_user, :read_cd_environment, object)

        environments = ::Cd::Environment.in_organization(object)
        environments = environments.with_tier(tier) if tier
        environments = environments.search(search) if search.present?
        environments = environments.for_application(application_id.model_id) if application_id
        environments = environments.with_status(status, organization: object) if status
        environments
      end
    end
  end
end
