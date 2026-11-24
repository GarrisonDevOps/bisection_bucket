# frozen_string_literal: true

module API
  module Entities
    class ExternalStatusCheck < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
      expose :name, documentation: { type: 'String', example: 'QA' }
      expose :project_id, documentation: { type: 'Integer', format: 'int64', example: 1 }
      expose :external_url, documentation: { type: 'String', example: 'https://www.example.com' }
      expose :protected_branches, using: ::API::Entities::ProtectedBranch, documentation: { is_array: true }
      expose :hmac?, as: :hmac, documentation: { type: 'Boolean', example: true }
    end
  end
end
