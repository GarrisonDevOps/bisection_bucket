# frozen_string_literal: true

module API
  module Entities
    module Scim
      class Error < Grape::Entity
        STATUS = 412

        expose :schemas, documentation: { type: 'String', is_array: true }
        expose :scim_type, as: :scimType, if: ->(error, _options) { error[:scim_type].present? },
          documentation: { type: 'String' }
        expose :detail, safe: true, documentation: { type: 'String' }
        expose :status, documentation: { type: 'Integer' }

        private

        DEFAULT_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error'

        def schemas
          [DEFAULT_SCHEMA]
        end

        def status
          self.class::STATUS
        end
      end
    end
  end
end
