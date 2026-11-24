# frozen_string_literal: true

module API
  module Entities
    module Scim
      class UserName < Grape::Entity
        expose :name, as: :formatted, documentation: { type: 'String' }
        expose :first_name, as: :givenName, documentation: { type: 'String' }
        expose :last_name, as: :familyName, documentation: { type: 'String' }
      end
    end
  end
end
