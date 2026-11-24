# frozen_string_literal: true

module Resolvers
  module Security
    class ProjectSecurityExclusionResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type Types::Security::ProjectSecurityExclusionType.connection_type, null: true

      authorize :read_project_security_exclusions

      description 'Find security scanner exclusions for a project.'

      when_single do
        argument :id, ::Types::GlobalIDType[::Security::ProjectSecurityExclusion],
          required: true,
          description: 'ID of the project security exclusion.'
      end

      argument :scanner, Types::Security::ExclusionScannerEnum, required: false,
        description: 'Filter entries by scanner.'

      argument :type, Types::Security::ExclusionTypeEnum, required: false,
        description: 'Filter entries by exclusion type.'

      argument :active, GraphQL::Types::Boolean, required: false,
        description: 'Filter entries by active status.'

      def resolve(**args)
        raise_resource_not_available_error! unless object.licensed_feature_available?(:security_exclusions)

        params = args[:id] ? { id: args[:id].model_id } : args

        ::Security::ProjectSecurityExclusionsFinder.new(current_user, project: object, params: params).execute
      end
    end
  end
end
