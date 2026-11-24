# frozen_string_literal: true

module Authz
  class UserAdminRole < ApplicationRecord
    self.primary_key = 'user_id'

    belongs_to :user
    belongs_to :admin_role, class_name: 'Authz::AdminRole'

    validates :admin_role, presence: true
    validates :user, presence: true, uniqueness: true

    scope :with_identity_provider, ->(provider) do
      joins(user: :identities).where(identities: { provider: provider })
    end

    scope :preload_user, -> { preload(:user) }

    def self.filter_users(users, admin_role_id)
      users.joins(:user_admin_role).where(user_admin_role: { admin_role_id: admin_role_id })
    end

    def self.create_or_update(user:, admin_role:, **args)
      find_or_initialize_by(user: user).tap do |record|
        record.update(admin_role: admin_role, **args)
      end
    end
  end
end
