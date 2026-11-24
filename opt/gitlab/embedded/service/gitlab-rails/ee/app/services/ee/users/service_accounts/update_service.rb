# frozen_string_literal: true

module EE
  module Users
    module ServiceAccounts
      module UpdateService
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        private

        # force_name_change bypasses the updating_name_disabled_for_users
        # restriction enforced by the EE extension of Users::UpdateService.
        # In CE, no such restriction exists - names are always updatable.
        override :update_params
        def update_params
          super.merge(force_name_change: true)
        end
      end
    end
  end
end
