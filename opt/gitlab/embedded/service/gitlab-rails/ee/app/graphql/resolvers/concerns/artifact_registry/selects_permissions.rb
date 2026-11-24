# frozen_string_literal: true

module ArtifactRegistry
  module SelectsPermissions
    extend ActiveSupport::Concern

    included do
      extras [:lookahead]
    end

    private

    def permissions_selected?(lookahead)
      lookahead.selects?(:user_permissions)
    end

    def connection_permissions_selected?(lookahead)
      permissions_selected?(lookahead) ||
        permissions_selected?(lookahead.selection(:nodes)) ||
        permissions_selected?(lookahead.selection(:edges).selection(:node))
    end
  end
end
