# frozen_string_literal: true

# rubocop:disable Gitlab/BoundedContexts -- the Achievements module already exists and holds the other services as well
module Achievements
  class UpdateUserAchievementService
    attr_reader :current_user, :user_achievement, :params

    def initialize(current_user, user_achievement, params)
      @current_user = current_user
      @user_achievement = user_achievement
      @params = params
    end

    def execute
      return error_no_permissions unless allowed?

      remove_unallowed_params

      if user_achievement.update(params)
        ServiceResponse.success(payload: user_achievement)
      else
        error_updating
      end
    end

    private

    def remove_unallowed_params
      unless Ability.allowed?(current_user, :update_user_achievement_show_on_profile, user_achievement)
        params.delete(:show_on_profile)
      end

      return if Ability.allowed?(current_user, :update_user_achievement_award_message, user_achievement)

      params.delete(:award_message)
    end

    def allowed?
      Ability.allowed?(current_user, :update_user_achievement, user_achievement)
    end

    def error_no_permissions
      error('You have insufficient permission to update this user achievement')
    end

    def error(message)
      ServiceResponse.error(payload: user_achievement, message: Array(message))
    end

    def error_updating
      error(user_achievement&.errors&.full_messages || 'Failed to update user achievement')
    end
  end
end
# rubocop:enable Gitlab/BoundedContexts
