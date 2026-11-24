# frozen_string_literal: true

module API
  module Entities
    module Scim
      class Emails < Grape::Entity
        expose :type, documentation: { type: 'String' }
        expose :value, documentation: { type: 'String' } do |user, _options|
          user.email
        end
        expose :primary, documentation: { type: 'Boolean' }

        private

        def type
          'work'
        end

        def primary
          true
        end
      end
    end
  end
end
