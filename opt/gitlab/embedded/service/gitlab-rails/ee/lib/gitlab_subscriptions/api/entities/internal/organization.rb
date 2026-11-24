# frozen_string_literal: true

module GitlabSubscriptions
  module API
    module Entities
      module Internal
        class Organization < Grape::Entity
          expose :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
          expose :name, documentation: { type: 'String', example: 'GitLab' }
        end
      end
    end
  end
end
