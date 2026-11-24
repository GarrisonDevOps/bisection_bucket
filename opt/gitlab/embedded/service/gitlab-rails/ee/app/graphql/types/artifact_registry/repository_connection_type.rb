# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class RepositoryConnectionType < GraphQL::Types::Relay::BaseConnection # rubocop:disable Graphql/AuthorizeTypes, GraphQL/GraphqlName -- the mounting field authorizes; graphql-ruby names the subclass it derives per node type
      field_class ::Types::BaseField

      # Not `expose_permissions`: that macro lives on `Types::BaseObject`, but this
      # type subclasses the gem's `BaseConnection`. It also can't take `experiment:`,
      # and it resolves `object.itself`, not `object.items.permissions`.
      field :user_permissions, ::Types::PermissionTypes::ArtifactRegistry::Namespace,
        null: false,
        experiment: { milestone: '19.5' },
        description: 'Permissions Artifact Registry grants the current user on the namespace the ' \
          'repositories belong to. Advisory, because Artifact Registry authorizes every request on its own. ' \
          'Every permission is `false` when Artifact Registry returned no verdicts. ' \
          'The parent field returns `null` when the `artifact_registry_ui` feature flag is ' \
          'disabled, so this block is not reached.'

      def user_permissions
        ::Types::PermissionTypes::ArtifactRegistry::Base::Block.new(
          verdicts: object.items.permissions, declaring_type: self.class.graphql_name
        )
      end
    end
  end
end
