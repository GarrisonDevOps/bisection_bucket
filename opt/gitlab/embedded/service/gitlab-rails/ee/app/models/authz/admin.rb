# frozen_string_literal: true

module Authz
  class Admin
    def initialize(user)
      @user = user
    end

    def permitted
      return [] if prevent_admin_area_access?

      available_permissions_for_user
    end

    def available_permissions_for_user
      ::Preloaders::UserMemberRolesForAdminPreloader
        .new(user: user)
        .execute[:admin]
    end

    private

    def prevent_admin_area_access?
      return false unless Gitlab::CurrentSettings.admin_mode

      !Gitlab::Auth::CurrentUserMode.new(user).admin_mode?
    end

    attr_reader :user
  end
end
