# frozen_string_literal: true

#
# Usage example:
#
# Groups::SyncService.new(
#   top_level_group, user,
#   group_links: array_of_group_links,
#   manage_group_ids: array_of_group_ids
# ).execute
#
# Given group links must respond to `group_id`, `access_level` and `member_role_id`.
#
# This is a generic group sync service, reusable by many IdP-specific
# implementations. The worker (caller) is responsible for providing the
# specific group links, which this service then iterates over
# and adds/removes users from respective groups. Users will only be
# removed from groups matching `manage_group_ids`.
#
# See `GroupSamlGroupSyncWorker` for an example.
#
module Groups
  class SyncService < Groups::BaseService
    include Gitlab::Utils::StrongMemoize
    include ::GitlabSubscriptions::MemberManagement::PromotionManagementUtils
    include GitlabSubscriptions::MemberManagement::SeatAwareProvisioning
    extend Gitlab::Utils::Override

    attr_reader :updated_membership

    override :initialize
    def initialize(group, user, params = {})
      @updated_membership = {
        added: 0,
        updated: 0,
        removed: 0
      }

      super
    end

    def execute
      return unless group

      remove_old_memberships
      update_current_memberships

      ServiceResponse.success(payload: updated_membership)
    ensure
      refresh_authorized_projects if refresh_priority
    end

    private

    attr_reader :refresh_priority

    def remove_old_memberships
      members_to_remove.each do |member|
        track_membership_change(UserProjectAccessChangedService::HIGH_PRIORITY)
        Members::DestroyService.new(member, current_user: current_user,
          skip_authorization: true, skip_subresources: true,
          skip_authorized_projects_refresh: true).execute

        next unless member.destroyed?

        log_membership_update(
          group_id: member.source_id,
          action: :removed,
          prior_access_level: member.access_level,
          access_level: nil,
          prior_member_role_id: member.member_role_id,
          member_role_id: nil
        )
      end
    end

    def update_current_memberships
      group_links_by_group.each do |group, group_links|
        group_link = max_access_level_group_link(group_links)
        requested_access_level = group_link.access_level
        access_level_adjustment = calculate_adjusted_access_level(group, current_user, requested_access_level)
        member_role_id = group_link.member_role_id if group.custom_roles_enabled?
        existing_member = existing_member_by_group(group)

        next if correct_access_level?(existing_member, access_level_adjustment.access_level, member_role_id)
        next if group.last_owner?(current_user)

        add_member(group, access_level_adjustment, existing_member, member_role_id, requested_access_level)
      end
    end

    def add_member(group, access_level_adjustment, existing_member, member_role_id, requested_access_level)
      access_level = access_level_adjustment.access_level
      # Any change to an existing membership can remove permissions, since access levels are not a strict hierarchy.
      track_membership_change(UserProjectAccessChangedService::HIGH_PRIORITY) if existing_member

      begin
        member = group.add_member(current_user, access_level, member_role_id: member_role_id,
          skip_authorized_projects_refresh: true)
      rescue StandardError
        # The membership may have been saved before an after_commit callback raised, and a retry skips it.
        track_membership_change(UserProjectAccessChangedService::MEDIUM_PRIORITY) unless existing_member
        raise
      end

      track_membership_saved_by_sync(member) unless existing_member

      return member unless member.persisted? && correct_access_level?(member, access_level, member_role_id)

      if access_level_adjustment.adjusted?
        track_and_audit_minimal_access_provisioning(group, member, requested_access_level)
      end

      log_membership_update(
        group_id: group.id,
        action: (existing_member ? :updated : :added),
        prior_access_level: existing_member&.access_level,
        access_level: access_level,
        prior_member_role_id: existing_member&.member_role_id,
        member_role_id: member_role_id
      )

      trigger_event_to_promote_pending_members!(member)
    end

    def correct_access_level?(member, access_level, member_role_id)
      member && member.access_level == access_level && member.member_role_id == member_role_id
    end

    def members_to_remove
      existing_members.select do |member|
        group_id = member.source_id

        !member_in_groups_to_be_updated?(group_id) && manage_group?(group_id)
      end
    end

    def member_in_groups_to_be_updated?(group_id)
      group_links_by_group.keys.map(&:id).include?(group_id)
    end

    def manage_group?(group_id)
      params[:manage_group_ids].include?(group_id)
    end

    def existing_member_by_group(group)
      existing_members.find { |member| member.source_id == group.id }
    end

    def existing_members
      strong_memoize(:existing_members) do
        group.members_with_descendants_including_minimal_access.with_user(current_user).to_a
      end
    end

    def group_links_by_group
      strong_memoize(:group_links_by_group) do
        params[:group_links].group_by(&:group)
      end
    end

    def max_access_level_group_link(group_links)
      # Return link with highest access level and for tie-breakers, return link with most recent member_role.
      group_links.max_by { |group_link| [group_link.access_level, group_link.member_role_id.to_i] }
    end

    def log_membership_update(group_id:, action:, prior_access_level:, access_level:, prior_member_role_id:, member_role_id:)
      @updated_membership[action] += 1

      Gitlab::AppLogger.info(
        class: self.class.name,
        user_id: current_user.id,
        action: action,
        group_id: group_id,
        prior_access_level: prior_access_level,
        new_access_level: access_level,
        prior_member_role_id: prior_member_role_id,
        new_member_role_id: member_role_id
      )
    end

    # A membership the sync created only grants access, so it needs a refresh only once saved.
    # A record that already existed (for example an access request) may have changed either way.
    def track_membership_saved_by_sync(member)
      return unless member.persisted?

      track_membership_change(
        member.previously_new_record? ? UserProjectAccessChangedService::MEDIUM_PRIORITY : UserProjectAccessChangedService::HIGH_PRIORITY
      )
    end

    # Removals and changes to existing members are tracked before they happen, so one that commits and then
    # raises still gets a refresh. They keep high priority so revoked access is applied without delay.
    # New memberships are tracked once saved.
    def track_membership_change(priority)
      return if refresh_priority == UserProjectAccessChangedService::HIGH_PRIORITY

      @refresh_priority = priority
    end

    # Callers such as Authn::SyncScimGroupMembersWorker run the sync inside a transaction,
    # and the refresh must not run before the membership changes are committed.
    def refresh_authorized_projects
      user_id = current_user.id
      priority = refresh_priority

      ActiveRecord.after_all_transactions_commit do
        UserProjectAccessChangedService.new(user_id).execute(priority: priority)
      end
    end
  end
end
