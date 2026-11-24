# frozen_string_literal: true

module EE
  module Authn
    module Users
      module TwoFactorGroupsFinder
        extend ::Gitlab::Utils::Override

        private

        override :groups_with_at_least_minimal_access
        def groups_with_at_least_minimal_access
          ::Group.from_union([super, user.available_minimal_access_groups])
        end
      end
    end
  end
end
