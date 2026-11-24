# frozen_string_literal: true

module API
  module Entities
    class DeployKeysProject < Grape::Entity
      expose :deploy_key, merge: true, using: ::API::Entities::DeployKey,
        documentation: { type: 'API::Entities::DeployKey' }
      expose :can_push, documentation: { type: 'Boolean' }
    end
  end
end
