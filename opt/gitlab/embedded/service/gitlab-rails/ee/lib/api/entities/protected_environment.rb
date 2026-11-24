# frozen_string_literal: true

module API
  module Entities
    class ProtectedEnvironment < Grape::Entity
      expose :name, documentation: { type: 'String', example: 'production' }
      expose :deploy_access_levels, using: ::API::Entities::ProtectedEnvironments::DeployAccessLevel, documentation: { is_array: true }
      expose :required_approval_count, documentation: { type: 'Integer', example: 2 }
      expose :approval_rules, using: ::API::Entities::ProtectedEnvironments::ApprovalRule, documentation: { is_array: true }
    end
  end
end
