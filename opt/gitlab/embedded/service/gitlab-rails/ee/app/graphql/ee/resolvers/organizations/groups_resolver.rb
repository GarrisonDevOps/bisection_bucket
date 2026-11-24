# frozen_string_literal: true

module EE
  module Resolvers
    module Organizations
      module GroupsResolver
        extend ::Gitlab::Utils::Override

        private

        override :finder_params
        def finder_params(args)
          super.merge(filter_expired_saml_session_groups: true)
        end
      end
    end
  end
end
