# frozen_string_literal: true

module Gitlab
  module Scim
    class GroupMembershipCacheService
      BATCH_SIZE = 1000

      attr_reader :scim_group_uid

      def initialize(scim_group_uid:)
        @scim_group_uid = scim_group_uid
      end

      def add_users(user_ids)
        return if user_ids.empty?

        now = Time.zone.now

        memberships = user_ids.map do |user_id|
          Authn::ScimGroupMembership.new(
            user_id: user_id, scim_group_uid: scim_group_uid, created_at: now, updated_at: now
          )
        end

        Authn::ScimGroupMembership.bulk_upsert!(
          memberships,
          unique_by: [:user_id, :scim_group_uid],
          batch_size: BATCH_SIZE,
          validate: false
        )
      end

      def remove_users(user_ids)
        return if user_ids.empty?

        Authn::ScimGroupMembership.by_scim_group_uid(scim_group_uid).by_user_id(user_ids)
          .each_batch(of: BATCH_SIZE) do |batch|
          batch.delete_all
        end
      end

      def replace_users(user_ids)
        Authn::ScimGroupMembership.by_scim_group_uid(scim_group_uid).each_batch(of: BATCH_SIZE) do |batch|
          batch.delete_all
        end

        add_users(user_ids)
      end
    end
  end
end
