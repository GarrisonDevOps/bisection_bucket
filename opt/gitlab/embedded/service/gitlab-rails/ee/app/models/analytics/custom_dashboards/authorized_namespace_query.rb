# frozen_string_literal: true

module Analytics
  module CustomDashboards
    class AuthorizedNamespaceQuery
      def self.for(user, organization:, min_access_level:)
        return Group.none unless user

        user
          .groups
          .where(members: { access_level: min_access_level.. })
          .self_and_descendants
          .in_organization(organization)
          .distinct
      end
    end
  end
end
