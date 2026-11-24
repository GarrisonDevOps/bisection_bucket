# frozen_string_literal: true

module API
  module Entities
    class DeployKeyWithUser < Entities::DeployKey
      expose :user, using: ::API::Entities::UserPublic,
        documentation: { type: 'API::Entities::UserPublic' }
      expose :deploy_keys_projects,
        documentation: { type: 'Hash', is_array: true }
    end
  end
end
