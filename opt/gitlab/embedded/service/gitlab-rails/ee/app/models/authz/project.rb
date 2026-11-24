# frozen_string_literal: true

module Authz
  class Project
    def initialize(user, scope:)
      @user = user
      @scope = scope
    end

    def permitted
      ::Preloaders::UserMemberRolesInProjectsPreloader
        .new(projects: scope, user: user)
        .execute
    end

    private

    attr_reader :user, :scope
  end
end
