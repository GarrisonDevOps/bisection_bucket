# frozen_string_literal: true

module Gitlab
  module Auth
    module GroupSaml
      class DuoAddOnAssignmentUpdater < Gitlab::Auth::Saml::DuoAddOnAssignmentUpdater
        include Gitlab::Utils::StrongMemoize
        extend ::Gitlab::Utils::Override

        attr_reader :user, :group, :auth_hash

        def initialize(user, group, auth_hash)
          @user = user
          @group = group
          @auth_hash = auth_hash
        end

        private

        override :preconditions_met?
        def preconditions_met?
          any_duo_group_links?
        end

        override :assign_duo_seat
        def assign_duo_seat
          return if existing_add_on_assignment?

          ::GitlabSubscriptions::AddOnPurchases::CreateUserAddOnAssignmentWorker.perform_async(user.id, group.id)
        end

        override :unassign_duo_seat
        def unassign_duo_seat
          return unless existing_add_on_assignment?

          ::GitlabSubscriptions::AddOnPurchases::DestroyUserAddOnAssignmentWorker.perform_async(user.id, group.id)
        end

        def any_duo_group_links?
          SamlGroupLink
            .by_group_id(group.id)
            .by_assign_duo_seats(true)
            .exists?
        end

        override :user_in_add_on_group?
        def user_in_add_on_group?
          SamlGroupLink
            .by_saml_group_name(group_names_from_saml)
            .by_group_id(group.id)
            .by_assign_duo_seats(true)
            .exists?
        end

        override :add_on_purchase
        def add_on_purchase
          ::GitlabSubscriptions::Duo.enterprise_or_pro_for_namespace(group)
        end
        strong_memoize_attr :add_on_purchase
      end
    end
  end
end
