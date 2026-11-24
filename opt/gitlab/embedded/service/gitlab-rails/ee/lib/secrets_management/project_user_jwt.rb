# frozen_string_literal: true

module SecretsManagement
  class ProjectUserJwt < ProjectSecretsManagerJwt
    def payload
      claims = super
      claims[:sub] = "user:#{current_user.username}"
      claims[:member_role_id] = member_role_id
      claims[:role_id] = role_id
      claims[:secrets_manager_scope] = 'user'
      claims
    end

    private

    def member_role_id
      return unless project.group

      group_member = current_user.members.find_by(source: project.group) # rubocop:disable CodeReuse/ActiveRecord -- We are using .where here because the models are ActiveRecord classes.
      return group_member.member_role.id.to_s if group_member&.member_role_id.present?

      project.group.ancestors.each do |ancestor|
        group_member = current_user.members.find_by(source: ancestor) # rubocop:disable CodeReuse/ActiveRecord -- We are using .where here because the models are ActiveRecord classes.
        return group_member.member_role.id.to_s if group_member&.member_role_id.present?
      end

      nil
    end

    def role_id
      current_user.max_member_access_for_project(project.id).to_s
    end
  end
end
