# frozen_string_literal: true

module Ai
  module HasRolePermissions
    extend ActiveSupport::Concern

    included do
      validates :minimum_access_level_execute,
        inclusion: { in: Gitlab::Access.sym_options_with_admin.values },
        numericality: { greater_than_or_equal_to: Gitlab::Access::GUEST },
        allow_nil: true

      validates :minimum_access_level_execute_async,
        inclusion: { in: Gitlab::Access.sym_options_with_admin.values },
        numericality: { greater_than_or_equal_to: Gitlab::Access::DEVELOPER },
        allow_nil: true

      validates :minimum_access_level_manage,
        inclusion: { in: Gitlab::Access.sym_options_with_admin.values },
        numericality: { greater_than_or_equal_to: Gitlab::Access::DEVELOPER },
        allow_nil: true

      validates :minimum_access_level_enable_on_projects,
        inclusion: { in: Gitlab::Access.sym_options_with_admin.values },
        numericality: { greater_than_or_equal_to: Gitlab::Access::DEVELOPER },
        allow_nil: true
    end
  end
end
