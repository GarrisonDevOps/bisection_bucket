# frozen_string_literal: true

module API
  module Entities
    module GitlabSubscriptions
      class AddOnPurchase < Grape::Entity
        expose :namespace_id, documentation: { type: 'Integer', format: 'int64', example: 123 }
        expose :namespace_name, documentation: { type: 'String', example: 'GitLab' }
        expose :add_on, documentation: { type: 'String', example: 'Code Suggestions' }
        expose :quantity, documentation: { type: 'Integer', example: 10 }
        expose :started_at, as: :started_on, documentation: { type: 'Date', example: '2023-05-30' }
        expose :expires_on, documentation: { type: 'Date', example: '2023-05-30' }
        expose :purchase_xid, documentation: { type: 'String', example: 'A-S00000001' }
        expose :trial, documentation: { type: 'Boolean', example: false }

        def namespace_name
          object.namespace.name
        end

        def add_on
          object.add_on.name.titleize
        end
      end
    end
  end
end
