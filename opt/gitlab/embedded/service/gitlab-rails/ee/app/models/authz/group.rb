# frozen_string_literal: true

module Authz
  class Group
    def initialize(user, scope:)
      @user = user
      @scope = scope
    end

    def permitted
      ::Preloaders::UserMemberRolesInGroupsPreloader
        .new(groups: scope, user: user)
        .execute
    end

    private

    attr_reader :user, :scope
  end
end
