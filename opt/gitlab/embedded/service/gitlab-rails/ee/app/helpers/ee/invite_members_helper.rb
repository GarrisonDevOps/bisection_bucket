# frozen_string_literal: true

module EE
  module InviteMembersHelper
    include ::GitlabSubscriptions::SubscriptionHelper
    include GroupLinksHelper
    extend ::Gitlab::Utils::Override

    override :common_invite_group_modal_data
    def common_invite_group_modal_data(source, _member_class)
      super.merge(
        free_user_cap_enabled: ::Namespaces::FreeUserCap::Enforcement.new(source.root_ancestor).enforce_cap?.to_s,
        free_users_limit: ::Namespaces::FreeUserCap.dashboard_limit,
        overage_members_modal_available: overage_members_modal_available.to_s,
        has_gitlab_subscription: gitlab_com_subscription?.to_s,
        invite_with_custom_role_enabled: custom_roles_enabled?(source).to_s,
        root_group_path: source.root_ancestor.full_path
      )
    end

    override :common_invite_modal_dataset
    def common_invite_modal_dataset(source)
      dataset = super

      free_user_cap = ::Namespaces::FreeUserCap::Enforcement.new(source.root_ancestor)

      if source.root_ancestor.trial_active? && free_user_cap.qualified_namespace?
        dataset[:active_trial_dataset] = ::Gitlab::Json.dump(active_trial_dataset(source))
      end

      if free_user_cap.enforce_cap?
        dataset[:users_limit_dataset] = ::Gitlab::Json.dump(
          users_limit_dataset(source, free_user_cap)
        )
      end

      if can?(current_user, :admin_licensed_seat, source.root_ancestor)
        if ::Gitlab::CurrentSettings.seat_control_block_overages?
          dataset[:has_bso_feature_enabled] = true.to_s
          dataset[:add_seats_href] = help_page_url(
            "subscriptions/manage_seats.md",
            anchor: "buy-more-seats"
          )
        else
          dataset[:add_seats_href] = add_seats_url(source.root_ancestor)
        end
      end

      dataset[:manage_member_roles_path] = manage_member_roles_path(source)
      dataset[:overage_members_modal_available] = overage_members_modal_available.to_s
      dataset[:has_gitlab_subscription] = gitlab_com_subscription?.to_s
      dataset[:root_group_path] = source.root_ancestor.full_path
      dataset[:seat_assignment_model_enabled] = ::GitlabSubscriptions::SeatAssignmentModel.enabled?(source).to_s

      dataset
    end

    def active_trial_dataset(source)
      {
        purchase_path: group_billings_path(source.root_ancestor),
        free_users_limit: ::Namespaces::FreeUserCap.dashboard_limit
      }
    end

    def users_limit_dataset(source, free_user_cap)
      alert_variant =
        if free_user_cap.enforce_cap?
          if free_user_cap.reached_limit?
            ::Namespaces::FreeUserCap::REACHED_LIMIT_VARIANT
          elsif free_user_cap.close_to_dashboard_limit?
            ::Namespaces::FreeUserCap::CLOSE_TO_LIMIT_VARIANT
          end
        end

      {
        alert_variant: alert_variant,
        new_trial_registration_path: new_trial_path(namespace_id: source.root_ancestor.id),
        members_path: group_usage_quotas_path(source.root_ancestor),
        purchase_path: group_billings_path(source.root_ancestor),
        remaining_seats: free_user_cap.remaining_seats,
        free_users_limit: ::Namespaces::FreeUserCap.dashboard_limit
      }
    end

    def overage_members_modal_available
      ::Gitlab::Saas.feature_available?(:overage_members_modal)
    end

    private

    def custom_roles_enabled?(source)
      return custom_role_for_project_link_enabled?(source) if source.is_a?(Project)

      source.custom_roles_enabled?
    end
  end
end
