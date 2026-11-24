# frozen_string_literal: true

class Gitlab::Seeder::AuthzRefreshEvents # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  def seed!
    return if ::Authz::ProjectAuthorizations::RefreshEvent.exists?

    project = Project.order(:id).first
    user = User.order(:id).first
    group_member = GroupMember.order(:id).first
    shared_group = Group.where.not(id: group_member&.source_id).order(:id).first
    return warn "\nSkipping authz refresh event seeds: no project, user, group member or second group" unless
      project && user && group_member && shared_group

    events = [
      { target_type: :project, target_id: project.id, status: :processed },
      { target_type: :user_in_project, target_id: user.id, scope_id: project.id, visible_at: 5.minutes.from_now },
      { target_type: :user_in_group, target_id: group_member.user_id, scope_id: group_member.source_id,
        first_queued_at: 1.hour.ago },
      { target_type: :user, target_id: user.id },
      { target_type: :namespace_subtree, target_id: project.namespace_id },
      { target_type: :namespace_project_group_links, target_id: project.namespace_id },
      { target_type: :group_group_link, target_id: group_member.source_id, scope_id: shared_group.id, attempts: 1,
        cursor: project.id }
    ]

    events.each { |attributes| ::Authz::ProjectAuthorizations::RefreshEvent.create!(attributes) }
    print '.'
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating authz refresh event data"

  Gitlab::Seeder::AuthzRefreshEvents.new.seed!
end
