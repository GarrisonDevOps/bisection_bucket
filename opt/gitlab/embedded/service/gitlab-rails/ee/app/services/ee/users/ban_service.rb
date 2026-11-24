# frozen_string_literal: true

module EE
  module Users
    module BanService
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize
      include ManagementBaseService

      private

      def event_name
        'ban_user'
      end

      def event_message
        'Banned user'
      end

      def paid_user?(user)
        strong_memoize_with(:paid_user, user) do
          user.enterprise_user? || user.belongs_to_paid_namespace?(exclude_trials: true)
        end
      end

      override :valid_state?
      def valid_state?(user)
        return false if paid_user?(user)

        super
      end

      override :state_error
      def state_error(user)
        return error(_("You cannot ban paid users."), :forbidden) if paid_user?(user)

        super
      end
    end
  end
end
