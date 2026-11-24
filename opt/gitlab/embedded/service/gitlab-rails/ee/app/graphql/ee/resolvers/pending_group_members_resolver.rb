# frozen_string_literal: true

module EE
  module Resolvers
    class PendingGroupMembersResolver < ::Resolvers::BaseResolver
      include ::Gitlab::Graphql::Authorize::AuthorizeResource

      authorizes_object!

      authorize :admin_group_member

      alias_method :group, :object

      def resolve
        return unless group.root?

        members = ::Member.distinct_awaiting_or_invited_for_group(group)
        offset_pagination(members)
      end
    end
  end
end
