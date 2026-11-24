# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    module UserAddOnAssignmentCommon
      include Gitlab::Utils::StrongMemoize

      private

      attr_reader :user_id, :root_namespace_id

      def user
        User.find_by_id(user_id)
      end
      strong_memoize_attr :user

      def root_namespace
        Group.find_by_id(root_namespace_id)
      end
      strong_memoize_attr :root_namespace

      def add_on_purchase
        GitlabSubscriptions::Duo.enterprise_or_pro_for_namespace(root_namespace)
      end
      strong_memoize_attr :add_on_purchase

      def assignment
        add_on_purchase&.assigned_users&.by_user(user)&.first
      end
      strong_memoize_attr :assignment
    end
  end
end
