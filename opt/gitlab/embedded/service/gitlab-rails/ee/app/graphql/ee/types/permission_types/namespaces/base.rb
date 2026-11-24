# frozen_string_literal: true

module EE
  module Types
    module PermissionTypes
      module Namespaces
        module Base
          extend ActiveSupport::Concern

          prepended do
            ability_field :generate_description
            ability_field :bulk_admin_epic
            ability_field :create_epic
          end
        end
      end
    end
  end
end
