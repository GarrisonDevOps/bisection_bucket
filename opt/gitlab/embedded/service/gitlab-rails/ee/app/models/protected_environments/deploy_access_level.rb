# frozen_string_literal: true

module ProtectedEnvironments
  class DeployAccessLevel < ApplicationRecord
    include Authorizable

    self.table_name = 'protected_environment_deploy_access_levels'

    belongs_to :protected_environment, inverse_of: :deploy_access_levels

    validates :access_level, allow_blank: true, inclusion: { in: ALLOWED_ACCESS_LEVELS }
    validates :group_inheritance_type, inclusion: { in: GROUP_INHERITANCE_TYPE.values }
    validates_with ExactlyOnePresentValidator, fields: [:access_level, :group_id, :user_id]
  end
end
