# frozen_string_literal: true

module GitlabSubscriptions
  class PreviewBillableUserChangeService
    include ::Gitlab::Utils::StrongMemoize
    include ::GitlabSubscriptions::BillableUsersUtils

    attr_reader :current_user, :target_namespace, :role, :add_group_id, :add_user_emails, :add_user_ids, :member_role_id

    def initialize(current_user:, target_namespace:, role:, **opts)
      @current_user     = current_user
      @target_namespace = target_namespace
      @role             = role
      @add_group_id     = opts[:add_group_id]    || nil
      @add_user_emails  = opts[:add_user_emails] || []
      @add_user_ids     = opts[:add_user_ids]    || []
      @member_role_id   = opts[:member_role_id]  || nil
    end

    def execute
      {
        success: true,
        data: {
          will_increase_overage: will_increase_overage?,
          new_billable_user_count: new_billable_user_count,
          seats_in_subscription: seats_in_subscription
        }
      }
    end

    private

    def all_added_user_ids
      ids = Set.new

      ids += filtered_add_user_ids
      ids += user_ids_from_added_emails
      ids += user_ids_from_added_group

      ids
    end

    def user_ids_from_added_emails
      return [] if filtered_add_user_emails.blank?

      User.by_any_email(filtered_add_user_emails).ids # rubocop:disable CodeReuse/ActiveRecord -- To avoid having a scope that does not return Activerecord::Relation
    end
    strong_memoize_attr :user_ids_from_added_emails

    def filtered_add_user_ids
      return [] if add_user_ids.blank?

      add_user_ids - User.by_ids(add_user_ids).service_accounts.ids # rubocop:disable CodeReuse/ActiveRecord -- To avoid having a scope that does not return Activerecord::Relation
    end
    strong_memoize_attr :filtered_add_user_ids

    def filtered_add_user_emails
      return [] if add_user_emails.blank?

      add_user_emails - User.by_any_email(add_user_emails).service_accounts.pluck(:email) # rubocop:disable CodeReuse/ActiveRecord -- To avoid having a scope that does not return Activerecord::Relation
    end
    strong_memoize_attr :filtered_add_user_emails

    def user_ids_from_added_group
      return [] if add_group_id.blank?

      group = GroupFinder.new(current_user).execute(id: add_group_id)

      return [] unless group

      group.billed_user_ids[:user_ids]
    end

    def will_increase_overage?
      return false unless reconciliation_enabled?

      new_billable_user_count > current_max_billable_users
    end

    def new_billable_user_count
      @new_billable_user_count ||= if increase_billable_members_count?
                                     unmatched_added_emails_count = (
                                       filtered_add_user_emails.count - user_ids_from_added_emails.count
                                     )

                                     (target_namespace.billed_user_ids[:user_ids].to_set + all_added_user_ids).count +
                                       unmatched_added_emails_count
                                   else
                                     target_namespace.billable_members_count
                                   end
    end

    def seats_in_subscription
      @seats_in_subscription ||= target_namespace.gitlab_subscription&.seats || 0
    end

    def current_max_billable_users
      [target_namespace.billable_members_count, seats_in_subscription].max
    end

    def increase_billable_members_count?
      if gitlab_com_subscription?
        saas_billable_role_change?(
          target_namespace: target_namespace,
          role: ::Gitlab::Access.sym_options_with_owner[role],
          member_role_id: member_role_id
        )
      else
        sm_billable_role_change?(
          role: ::Gitlab::Access.sym_options_with_owner[role],
          member_role_id: member_role_id
        )
      end
    rescue ::GitlabSubscriptions::BillableUsersUtils::InvalidMemberRoleError
      false
    end

    def reconciliation_enabled?
      GitlabSubscriptions::Reconciliations::CheckSeatUsageAlertsEligibilityService.new(
        namespace: target_namespace,
        skip_cached: true
      ).execute
    end
  end
end

GitlabSubscriptions::PreviewBillableUserChangeService.prepend_mod
