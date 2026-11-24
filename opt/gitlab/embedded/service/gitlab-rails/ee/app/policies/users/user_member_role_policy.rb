# frozen_string_literal: true

module Users
  class UserMemberRolePolicy < BasePolicy
    delegate { :global }
  end
end
