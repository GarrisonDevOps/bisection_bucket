# frozen_string_literal: true

module Types
  module Members
    module PendingMemberInterface
      include BaseInterface

      implements MemberInterface

      orphan_types PendingGroupMemberType, PendingProjectMemberType

      field :name,
        type: GraphQL::Types::String,
        null: true,
        description: 'Name of the pending member.'

      field :username,
        type: GraphQL::Types::String,
        null: true,
        description: 'Username of the pending member.'

      field :email,
        type: GraphQL::Types::String,
        null: true,
        description: "Public email of the pending member."

      field :web_url,
        type: GraphQL::Types::String,
        null: true,
        description: 'Web URL of the pending member.'

      field :avatar_url,
        type: GraphQL::Types::String,
        null: true,
        description: "URL to avatar image file of the pending member."

      field :approved,
        type: GraphQL::Types::Boolean,
        null: true,
        description: "Whether the pending member has been approved.",
        method: :active?

      field :invited,
        type: GraphQL::Types::Boolean,
        null: true,
        description: "Whether the pending member has been invited.",
        method: :invite?

      def name
        object.user&.name
      end

      def username
        object.user&.username
      end

      def email
        object.invite_email || object.user.public_email
      end

      def web_url
        return unless object.user.present?

        Gitlab::Routing.url_helpers.user_url(object.user)
      end

      def avatar_url
        object.user&.avatar_url || GravatarService.new.execute(email)
      end

      definition_methods do
        def resolve_type(object, _context)
          case object
          when GroupMember
            PendingGroupMemberType
          when ProjectMember
            PendingProjectMemberType
          else
            raise ::Gitlab::Graphql::Errors::BaseError, "Unknown member type #{object.class.name}"
          end
        end
      end
    end
  end
end
