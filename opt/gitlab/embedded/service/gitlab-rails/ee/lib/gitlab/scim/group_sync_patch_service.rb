# frozen_string_literal: true

module Gitlab
  module Scim
    class GroupSyncPatchService
      FILTER_PATH_ERROR = 'Filter paths are only supported for removing a member with members[value eq "<id>"]'
      REMOVE_WITHOUT_PATH_ERROR = 'Removing from a group requires a path'
      INVALID_MEMBERS_ERROR = 'Group members must be a list of objects that each have a string value'
      FULL_MEMBER_SYNC_COMBINED_ERROR = "Replacing or removing all group members can't be combined with other member " \
        "changes in the same request"
      CONFLICTING_MEMBER_ERROR = "The same member can't be added and removed in the same request"

      attr_reader :scim_group_uid, :operations

      def initialize(scim_group_uid:, operations:)
        @scim_group_uid = scim_group_uid
        @operations = operations.map { |operation| GroupPatchOperation.new(operation) }
      end

      def execute
        error_message = request_error_message
        return ServiceResponse.error(message: error_message) if error_message

        attribute_error = GroupAttributeCheck.new(scim_group_uid: scim_group_uid).error_for(
          display_names: operations.map(&:display_name),
          external_ids: operations.map(&:external_id)
        )
        return attribute_error if attribute_error

        operations.each do |operation|
          if operation.add?
            process_add_members(operation.members)
          elsif operation.removes_all_members?
            process_replace_members([])
          elsif operation.remove?
            process_remove_members(operation.members)
          elsif operation.replace?
            process_replace_members(operation.members)
          end
        end

        ServiceResponse.success
      end

      private

      def request_error_message
        return FILTER_PATH_ERROR unless operations.all?(&:supported_filter_path?)
        return REMOVE_WITHOUT_PATH_ERROR if operations.any?(&:remove_without_path?)
        return INVALID_MEMBERS_ERROR unless operations.all?(&:valid_members?)
        return FULL_MEMBER_SYNC_COMBINED_ERROR if full_member_sync_combined?

        CONFLICTING_MEMBER_ERROR if adds_and_removes_same_member?
      end

      # Each operation queues its own job and Sidekiq doesn't keep their order, so a full member sync
      # next to another member change could leave a different result depending on which job runs first.
      def full_member_sync_combined?
        member_operations = operations.select(&:changes_members?)

        member_operations.size > 1 && member_operations.any?(&:full_member_sync?)
      end

      # Each operation queues its own job and Sidekiq doesn't keep their order, so an add and a remove
      # of the same member could leave the member in or out depending on which job runs first.
      def adds_and_removes_same_member?
        added = member_extern_uids(operations.select(&:add?))
        removed = member_extern_uids(operations.select(&:remove?))

        added.intersect?(removed)
      end

      def member_extern_uids(operations)
        operations.flat_map(&:member_extern_uids).map { |extern_uid| extern_uid.to_s.downcase }
      end

      def process_add_members(members)
        return unless members.is_a?(Array)

        user_ids = collect_user_ids_from_members(members)
        return if user_ids.empty?

        ::Authn::SyncScimGroupMembersWorker.perform_async(scim_group_uid, user_ids, 'add')
      end

      def process_remove_members(members)
        return unless members.is_a?(Array)

        user_ids = collect_user_ids_from_members(members)
        return if user_ids.empty?

        ::Authn::SyncScimGroupMembersWorker.perform_async(scim_group_uid, user_ids, 'remove')
      end

      # Unlike add and remove, an empty list isn't skipped: replacing with no members removes
      # everyone synced through this SCIM group.
      def process_replace_members(members)
        return unless members.is_a?(Array)

        user_ids = collect_user_ids_from_members(members)

        ::Authn::SyncScimGroupMembersWorker.perform_async(scim_group_uid, user_ids, 'replace')
      end

      def collect_user_ids_from_members(members)
        ScimIdentity.instance_user_ids_by_extern_uids(members.filter_map { |member| member[:value] })
      end
    end
  end
end
