# frozen_string_literal: true

module Users
  class UserMemberRole < ApplicationRecord
    self.table_name = 'user_member_roles'

    belongs_to :member_role
    belongs_to :user

    validates :member_role, presence: true
    validates :user, presence: true, uniqueness: true

    scope :ldap_synced, -> { where(ldap: true) }

    scope :with_identity_provider, ->(provider) do
      joins(user: :identities).where(identities: { provider: provider })
    end

    scope :preload_user, -> { preload(:user) }

    def self.filter_users(users, member_role_id)
      users.joins(:user_member_role).where(user_member_role: { member_role_id: member_role_id })
    end

    def self.create_or_update(user:, member_role:, **args)
      find_or_initialize_by(user: user).tap do |record|
        record.update(member_role: member_role, **args)
      end
    end
  end
end
