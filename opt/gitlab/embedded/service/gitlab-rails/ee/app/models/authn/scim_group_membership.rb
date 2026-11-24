# frozen_string_literal: true

module Authn
  class ScimGroupMembership < ApplicationRecord
    include BulkInsertSafe

    self.table_name = 'scim_group_memberships'

    belongs_to :user, optional: false

    validates :scim_group_uid, presence: true
    validates :user, uniqueness: { scope: :scim_group_uid }

    scope :by_scim_group_uid, ->(scim_group_uid) { where(scim_group_uid: scim_group_uid) }
    scope :by_user_id, ->(user_id) { where(user_id: user_id) }
    scope :excluding_scim_group_uid, ->(scim_group_uid) { where.not(scim_group_uid: scim_group_uid) }

    def self.user_ids_to_remove_for_replace(scim_group_uid, target_user_ids)
      by_scim_group_uid(scim_group_uid).where.not(user_id: target_user_ids).select(:user_id)
    end

    # Returns the memberships for the given SCIM groups joined to each member's instance-level
    # SCIM identity, exposing the member's SCIM id (`member_extern_uid`) and display name
    # (`member_name`) alongside `scim_group_uid`. Returns a relation so callers can group and
    # shape the rows as needed (see API::Scim::InstanceScim#scim_members_for).
    def self.members_by_scim_group_uid(scim_group_uids)
      return none if scim_group_uids.blank?

      by_scim_group_uid(scim_group_uids)
        .joins(user: :instance_scim_identities)
        .select(
          'scim_group_memberships.scim_group_uid',
          'scim_identities.extern_uid AS member_extern_uid',
          'users.name AS member_name'
        )
    end
  end
end
