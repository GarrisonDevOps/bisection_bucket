# frozen_string_literal: true

class GroupScimIdentity < ApplicationRecord # rubocop:disable Gitlab/NamespacedClass,Gitlab/BoundedContexts -- Split from existing file
  include Sortable
  include CaseSensitivity
  include ScimPaginatable

  ignore_column :temp_source_id, remove_with: '18.8', remove_after: '2025-12-22'

  belongs_to :group
  belongs_to :user

  validates :user, presence: true, uniqueness: { scope: [:group_id] }
  validates :extern_uid, presence: true,
    uniqueness: { case_sensitive: false, scope: [:group_id] }

  scope :for_user, ->(user) { where(user: user) }
  scope :with_extern_uid, ->(extern_uid) { iwhere(extern_uid: extern_uid) }
end
