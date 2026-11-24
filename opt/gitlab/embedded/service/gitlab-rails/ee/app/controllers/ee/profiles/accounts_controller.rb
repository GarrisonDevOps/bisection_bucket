# frozen_string_literal: true

module EE
  module Profiles::AccountsController
    extend ::Gitlab::Utils::Override

    private

    override :show_view_variables
    def show_view_variables
      designated_account_manager = current_user.designated_account_manager
      designated_account_successor = current_user.designated_account_successor

      super.merge(
        designated_account_manager: designated_account_manager,
        designated_account_successor: designated_account_successor
      )
    end
  end
end
