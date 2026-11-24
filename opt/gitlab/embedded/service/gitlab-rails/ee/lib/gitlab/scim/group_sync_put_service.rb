# frozen_string_literal: true

module Gitlab
  module Scim
    class GroupSyncPutService
      attr_reader :scim_group_uid, :members, :display_name, :external_id

      def initialize(scim_group_uid:, members:, display_name:, external_id: nil)
        @scim_group_uid = scim_group_uid
        @members = members
        @display_name = display_name
        @external_id = external_id
      end

      def execute
        attribute_error = GroupAttributeCheck.new(scim_group_uid: scim_group_uid).error_for(
          display_names: [display_name],
          external_ids: [external_id]
        )
        return attribute_error if attribute_error

        sync_group_membership

        ServiceResponse.success
      end

      private

      def sync_group_membership
        return unless members.is_a?(Array)

        normalized_members = members.reject(&:blank?)
        extern_uids = normalized_members.filter_map { |member| member[:value] }
        target_user_ids = ScimIdentity.instance_user_ids_by_extern_uids(extern_uids)

        ::Authn::SyncScimGroupMembersWorker.perform_async(scim_group_uid, target_user_ids, 'replace')
      end
    end
  end
end
