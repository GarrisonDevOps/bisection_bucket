# frozen_string_literal: true

# This model records member role assignment to a user in projects through:
# - Project membership
# - Project sharing
#
# shared_with_group_id is nil for assignments through project membership.
#
# For assignments through project sharing project_id points to the shared project
# (project_group_link.shared_from) while shared_with_group_id ==
# project_group_link.shared_with_group_id. The shared_with_group_id column serves
# as a differentiator between different types of member role assignments as well
# as a way to easily delete records when the matching project_group_link record is
# deleted or the user's membership to shared_with_group is removed.
module Authz
  class UserProjectMemberRole < ApplicationRecord
    belongs_to :user
    belongs_to :project, class_name: '::Project'
    belongs_to :shared_with_group, class_name: '::Group', optional: true
    belongs_to :member_role

    validates :user, presence: true, uniqueness: { scope: %i[project_id shared_with_group_id] }
    validates :project, presence: true
    validates :member_role, presence: true

    scope :for_user_shared_with_group, ->(user, group) { where(user: user, shared_with_group: group) }

    scope :in_project_shared_with_group, ->(project, shared_with_group) do
      where(project: project, shared_with_group: shared_with_group)
    end

    def self.delete_all_with_id(ids)
      id_in(ids).delete_all
    end
  end
end
