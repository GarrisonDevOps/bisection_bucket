# frozen_string_literal: true

module EE
  module AntiAbuse
    module BanDuplicateUsersWorker
      extend ::Gitlab::Utils::Override

      private

      override :ban_user!
      def ban_user!(user, reason)
        return if user.enterprise_user?
        return if user.belongs_to_paid_namespace?(exclude_trials: true)

        super
      end
    end
  end
end
