# frozen_string_literal: true

module Types
  module ArtifactRegistry
    # A projection of one IAM relationship tuple returned by the lookup. The
    # rows come pre-authorized: IAM only returns assignments the caller may
    # see, so there is no per-object ability to check here.
    # rubocop: disable Graphql/AuthorizeTypes -- reads are authorized upstream by IAM
    class RoleAssignmentType < BaseObject
      graphql_name 'ArtifactRegistryRoleAssignment'
      description 'A direct role assignment. A user, the Artifact Registry role they hold, ' \
        'and the resource it is assigned on. Does not represent inherited access.'

      GRANTABLE_ROLES = ::Types::ArtifactRegistry::RoleEnum.values.values.map(&:value).freeze

      field :resource_id, GraphQL::Types::String,
        null: false,
        description: 'UUID of the Artifact Registry resource the role is assigned on.'

      field :role, ::Types::ArtifactRegistry::RoleEnum,
        null: true,
        description: 'Assigned Artifact Registry role. Null for platform roles such as Organization ' \
          'Administrator, which `assignedRole` covers.'

      field :assigned_role, ::Types::ArtifactRegistry::AssignedRoleType,
        null: true,
        experiment: { milestone: '19.6' },
        description: 'Assigned role, including platform roles such as Organization Administrator.'

      field :assignee, ::Types::UserType,
        null: true,
        description: 'User the role is assigned to.'

      field :granted_by, ::Types::UserType,
        null: true,
        description: 'User who granted the role. Null when unknown, for example for grants made before ' \
          'this field existed or by a user who was deleted.'

      field :created_at, ::Types::TimeType,
        null: true,
        description: 'Time the assignment was created.'

      # Long form of expose_permissions, which takes no `experiment:` option.
      field :user_permissions, ::Types::PermissionTypes::ArtifactRegistry::RoleAssignment,
        null: false,
        method: :itself,
        experiment: { milestone: '19.6' },
        description: 'Actions the current user can take on the assignment.'

      # `object` is the IAM relationship tuple; `object.object` is its resource.
      def resource_id
        object.object.id
      end

      # Platform roles such as Organization Administrator are not in NAMES and
      # resolve to nil; a known AR role missing from RoleEnum is drift.
      def role
        role_key = ::ArtifactRegistry::Roles.name_for(object.role&.id)
        return role_key if grantable_role?(role_key)

        log_ungrantable_role(role_key) if role_key

        nil
      end

      def assigned_role
        ::Gitlab::Glaz.roles.find { |role| role[:id] == object.role&.id }
      end

      def assignee
        # subject.id is a oneof: identity or principal. The lookup returns
        # identities today; a principal-shaped subject has no local user id,
        # so it surfaces as a nil assignee rather than an error.
        local_id = object.subject.identity&.local_id
        return unless local_id

        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::User, local_id).find
      end

      # LookupResources does not set granted_by, so assignments it returns
      # (the assigneeIds path for organization owners) resolve to nil.
      def granted_by
        local_id = object.granted_by&.identity&.local_id
        return unless local_id

        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::User, local_id).find
      end

      def created_at
        object.timestamp&.to_time
      end

      private

      def grantable_role?(role_key)
        GRANTABLE_ROLES.include?(role_key)
      end

      # Signals NAMES/RoleEnum drift, which otherwise surfaces only as a
      # silent null field with nothing to alert on.
      def log_ungrantable_role(role_key)
        Gitlab::AppLogger.warn(
          message: 'ArtifactRegistryRoleAssignment#role resolved to a role RoleEnum does not declare',
          role_key: role_key
        )
      end
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
