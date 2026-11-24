# frozen_string_literal: true

module API
  module Entities
    module Namespaces
      module Storage
        class LimitExclusion < Grape::Entity
          expose :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
          expose :namespace_id, documentation: { type: 'Integer', format: 'int64', example: 123 }
          expose :namespace_name, documentation: { type: 'String', example: 'GitLab' }
          expose :reason, documentation: { type: 'String', example: 'a reason' }

          private

          def namespace_name
            object.namespace.name
          end
        end
      end
    end
  end
end
