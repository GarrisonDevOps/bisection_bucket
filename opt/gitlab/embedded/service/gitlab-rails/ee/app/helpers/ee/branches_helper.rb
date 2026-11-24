# frozen_string_literal: true

module EE
  module BranchesHelper
    extend ::Gitlab::Utils::Override

    def preselected_push_access_levels_data(access_levels, can_push)
      return [{ id: nil, type: :role, access_level: ::Gitlab::Access::NO_ACCESS }] unless can_push

      access_levels_data(access_levels)
    end

    override :access_levels_data
    def access_levels_data(access_levels)
      return [] unless access_levels

      access_levels.map do |level|
        case level.type
        when :user
          {
            id: level.id,
            type: level.type,
            user_id: level.user_id,
            username: level.user.username,
            name: level.user.name,
            avatar_url: level.user.avatar_url
          }
        when :deploy_key
          { id: level.id, type: level.type, deploy_key_id: level.deploy_key_id }
        when :group
          { id: level.id, type: level.type, group_id: level.group_id }
        when :member_role
          { id: level.id, type: level.type, member_role_id: level.member_role_id }
        else
          { id: level.id, type: level.type, access_level: level.access_level }
        end
      end
    end
  end
end
