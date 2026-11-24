# frozen_string_literal: true

module EE
  module Resolvers
    module Organizations
      module OrganizationUsersResolver
        extend ::Gitlab::Utils::Override

        private

        override :preloads
        def preloads
          super.merge({
            badges: [{ user: [:identities, :member_role] }]
          })
        end
      end
    end
  end
end
