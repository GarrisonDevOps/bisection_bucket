# frozen_string_literal: true

module EE
  module Members
    module InviteUsersFinder
      extend ::Gitlab::Utils::Override
      include ::Gitlab::Utils::StrongMemoize

      private

      def root_group
        root_ancestor = resource.root_ancestor

        root_ancestor if root_ancestor.group_namespace?
      end
      strong_memoize_attr :root_group

      override :scope_for_resource
      def scope_for_resource(users)
        users = by_seat_assignments(users)
        users = by_single_sign_on(users)

        super
      end

      def by_seat_assignments(users)
        return users unless seat_assignment_model_enabled?

        users.with_seat_assignment_in(root_group)
      end

      def by_single_sign_on(users)
        return users unless single_sign_on_enforced?

        users.with_single_sign_on_access_to(root_group)
      end

      def seat_assignment_model_enabled?
        ::GitlabSubscriptions::SeatAssignmentModel.enabled?(root_group)
      end

      def single_sign_on_enforced?
        root_group&.enforced_sso?
      end
    end
  end
end
