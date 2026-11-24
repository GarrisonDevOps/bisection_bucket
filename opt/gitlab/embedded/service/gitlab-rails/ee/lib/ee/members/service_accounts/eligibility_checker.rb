# frozen_string_literal: true

module EE
  module Members
    module ServiceAccounts
      module EligibilityChecker
        extend ::Gitlab::Utils::Override

        private

        override :composite_identity_restrictions_enabled?
        def composite_identity_restrictions_enabled?
          ::Gitlab::Saas.feature_available?(:service_accounts_invite_restrictions)
        end
      end
    end
  end
end
