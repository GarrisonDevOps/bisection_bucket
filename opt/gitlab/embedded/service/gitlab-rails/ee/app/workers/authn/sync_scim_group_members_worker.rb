# frozen_string_literal: true

module Authn
  class SyncScimGroupMembersWorker
    include ApplicationWorker
    include GitlabSubscriptions::MemberManagement::SeatAwareProvisioning

    feature_category :user_management
    data_consistency :sticky

    idempotent!

    loggable_arguments 0, 1, 2

    # Processes SCIM group membership changes in the background.
    #
    # +scim_group_uid+ - The SCIM group UID to process
    # +user_ids+ - Array of user IDs to add, remove, or replace
    # +operation_type+ - 'add', 'remove', or 'replace'
    def perform(scim_group_uid, user_ids, operation_type)
      unless %w[add remove replace].include?(operation_type.to_s)
        Gitlab::AppLogger.warn(
          message: 'Unsupported SCIM group membership operation',
          operation_type: operation_type,
          scim_group_uid: scim_group_uid
        )
        return
      end

      @scim_group_uid = scim_group_uid
      @user_ids = user_ids
      @cache_service = ::Gitlab::Scim::GroupMembershipCacheService.new(scim_group_uid: scim_group_uid)

      return if group_links.empty?
      return if user_ids.empty? && operation_type != 'replace'

      ApplicationRecord.transaction do
        lock_linked_groups

        case operation_type.to_s
        when 'add'
          process_add_members
        when 'remove'
          process_remove_members
        when 'replace'
          process_replace_members
        end
      end
    end

    private

    attr_reader :scim_group_uid, :user_ids, :cache_service

    # Adding a member or changing their role locks the group until this transaction commits. Taking every
    # group's lock up front in id order stops two jobs that share groups from deadlocking. The flag is
    # checked per group so this matches the groups that member creation will lock later.
    def lock_linked_groups
      Group.id_in(group_links.map(&:group_id)).sort_by(&:id).each do |group|
        Member.lock_source(group) if Feature.enabled?(:lock_member_creation, group)
      end
    end

    def process_add_members
      cache_service.add_users(user_ids)

      users = User.by_ids(user_ids)
      add_members_to_linked_groups(users)
    end

    def process_remove_members
      cache_service.remove_users(user_ids)

      users = User.by_ids(user_ids)
      remove_members_from_linked_groups(users)
    end

    def process_replace_members
      user_ids_to_remove = Authn::ScimGroupMembership.user_ids_to_remove_for_replace(scim_group_uid, user_ids)
      users_to_remove = User.by_ids(user_ids_to_remove)

      remove_members_from_linked_groups(users_to_remove) if users_to_remove.any?

      cache_service.replace_users(user_ids)

      return unless user_ids.any?

      users_to_add = User.by_ids(user_ids)
      add_members_to_linked_groups(users_to_add)
    end

    def add_members_to_linked_groups(users)
      grouped_links = group_links.group_by(&:group_id)

      grouped_links.each_value do |links|
        group = links.first.group
        next unless group

        highest_access_level = links.map(&:access_level).max

        users.each do |user|
          existing_member = group.members.by_user_id(user.id).first
          next if existing_member && existing_member.access_level >= highest_access_level

          access_level_adjustment = calculate_adjusted_access_level(
            group, user, highest_access_level, { scim_group_uid: scim_group_uid }
          )
          member = group.add_member(user, access_level_adjustment.access_level)

          next unless member.persisted? && access_level_adjustment.adjusted?

          track_and_audit_minimal_access_provisioning(
            group, member, highest_access_level, { scim_group_uid: scim_group_uid }
          )
        end
      end
    end

    # Removes users from GitLab groups that are linked to the current SCIM group,
    # while preserving their membership if they belong to other SCIM groups that
    # also link to the same GitLab groups.
    #
    # This method uses batched queries to avoid N+1 problems when processing
    # multiple users and groups.
    #
    # Example scenario:
    #   - Current SCIM group: "developers" (being removed from)
    #   - User Alice belongs to SCIM groups: ["developers", "admins"]
    #   - GitLab Group "project-team" is linked to both "developers" and "admins"
    #   - Result: Alice keeps access to "project-team" because she's still in "admins"
    #
    #   - User Bob belongs to SCIM groups: ["developers"] only
    #   - GitLab Group "project-team" is linked to "developers"
    #   - Result: Bob loses access to "project-team" because no other SCIM groups maintain it
    #
    # +users+ - Array of users to potentially remove from linked groups
    def remove_members_from_linked_groups(users)
      grouped_links = group_links.group_by(&:group_id)
      batch_data = build_batch_data_for_removal(users)

      grouped_links.each_value do |links|
        process_group_member_removal(links, users, batch_data)
      end
    end

    def build_batch_data_for_removal(users)
      user_ids = users.map(&:id)
      retained_memberships = fetch_retained_scim_memberships(user_ids)

      {
        memberships_by_user: retained_memberships.group_by(&:user_id),
        group_links_by_scim_uid: fetch_and_group_retained_group_links(retained_memberships)
      }
    end

    def fetch_retained_scim_memberships(user_ids)
      Authn::ScimGroupMembership
        .by_user_id(user_ids)
        .excluding_scim_group_uid(scim_group_uid)
    end

    def fetch_and_group_retained_group_links(retained_memberships)
      all_retained_scim_group_uids = retained_memberships.map(&:scim_group_uid).uniq
      all_retained_group_links = SamlGroupLink.by_scim_group_uid(all_retained_scim_group_uids)
      all_retained_group_links.group_by(&:scim_group_uid)
    end

    def process_group_member_removal(links, users, batch_data)
      # All group links in the `links` array belong to the same GitLab group since they were
      # grouped by `group_id` in `remove_members_from_linked_groups`
      group = links.first.group

      users.each do |user|
        sync_user_group_membership(group, user, batch_data) if group.member?(user)
      end
    end

    # Only links to the group being managed are passed. Groups::SyncService adds the user to every group in
    # its links, so passing links to other groups would change, and lock, groups this job didn't lock up front.
    def sync_user_group_membership(group, user, batch_data)
      retained_group_links = get_user_retained_group_links(user, batch_data).select { |link| link.group_id == group.id }

      ::Groups::SyncService.new(
        group,
        user,
        {
          group_links: retained_group_links,
          manage_group_ids: [group.id]
        }
      ).execute
    end

    def get_user_retained_group_links(user, batch_data)
      user_retained_memberships = batch_data[:memberships_by_user][user.id] || []
      retained_scim_group_uids = user_retained_memberships.map(&:scim_group_uid)

      retained_scim_group_uids.flat_map do |uid|
        batch_data[:group_links_by_scim_uid][uid] || []
      end
    end

    def group_links
      @group_links ||= SamlGroupLink.by_scim_group_uid(@scim_group_uid)
    end
  end
end
