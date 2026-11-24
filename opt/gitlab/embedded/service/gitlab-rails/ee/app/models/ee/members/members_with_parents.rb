# frozen_string_literal: true

module EE
  module Members
    module MembersWithParents
      extend ::Gitlab::Utils::Override

      private

      override :filter_invites_and_requests
      def filter_invites_and_requests(members, minimal_access)
        return super unless minimal_access
        return super unless group.minimal_access_role_allowed?

        members.without_invites_and_requests(minimal_access: minimal_access)
      end
    end
  end
end
