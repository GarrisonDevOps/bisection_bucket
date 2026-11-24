# frozen_string_literal: true

class UserGroupsCounter
  def initialize(user_ids, organization: nil)
    @user_ids = user_ids
    @organization = organization
  end

  def execute
    Namespace.unscoped do
      Namespace.from_union([
        by_organization(groups),
        project_groups
      ]).group(:user_id).count # rubocop: disable CodeReuse/ActiveRecord -- Union query requires ActiveRecord group/count
    end
  end

  private

  attr_reader :user_ids, :organization

  def groups
    Group.for_authorized_group_members(user_ids)
      .select('namespaces.id, members.user_id as user_id')
  end

  def project_groups
    ProjectAuthorization.for_project_groups(user_ids, organization: organization)
  end

  def by_organization(items)
    return items unless organization

    items.in_organization(organization)
  end
end
