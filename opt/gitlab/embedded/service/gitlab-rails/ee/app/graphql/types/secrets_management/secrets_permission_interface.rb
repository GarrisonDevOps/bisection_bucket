# frozen_string_literal: true

module Types
  module SecretsManagement
    module SecretsPermissionInterface
      extend ActiveSupport::Concern

      included do
        field :principal,
          Types::SecretsManagement::Permissions::PrincipalType,
          null: false,
          description: 'Who is provided access to. For eg: User/Role/MemberRole.'

        field :actions,
          [Types::SecretsManagement::Permissions::ActionEnum],
          null: false,
          description: 'Actions that can be performed on secrets.'

        field :granted_by,
          Types::UserType,
          null: true,
          description: "User who created the Secret Permission."

        field :expired_at,
          type: GraphQL::Types::ISO8601Date,
          null: true,
          description: "Expiration date for Secret Permission (optional)."
      end

      def granted_by
        Gitlab::Graphql::Loaders::BatchModelLoader.new(User, object.granted_by).find
      end

      def principal
        {
          id: object.principal_id.to_s,
          type: object.principal_type.to_s,
          resource_id: object.resource.id.to_s,
          resource_type: object.resource.class.name
        }
      end
    end
  end
end
