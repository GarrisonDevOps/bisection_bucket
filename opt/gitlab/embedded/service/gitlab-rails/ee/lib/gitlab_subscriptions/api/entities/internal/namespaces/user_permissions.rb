# frozen_string_literal: true

module GitlabSubscriptions
  module API
    module Entities
      module Internal
        module Namespaces
          class UserPermissions < Grape::Entity
            expose :edit_billing, documentation: { type: 'Boolean' }
          end
        end
      end
    end
  end
end
