# frozen_string_literal: true

module Types
  module PermissionTypes
    module MergeTrains
      class Car < BasePermissionType
        graphql_name 'CarPermissions'
        description "Check user's permission for the car."

        abilities :delete_merge_train_car
      end
    end
  end
end
