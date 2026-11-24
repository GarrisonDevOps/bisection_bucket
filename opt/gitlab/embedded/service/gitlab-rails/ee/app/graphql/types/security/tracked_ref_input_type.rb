# frozen_string_literal: true

module Types
  module Security
    class TrackedRefInputType < Types::BaseInputObject
      graphql_name 'SecurityRefInput'

      argument :name, GraphQL::Types::String,
        required: true,
        description: 'Name of the ref.'

      argument :ref_type, Types::Security::TrackedRefTypeEnum,
        required: true,
        description: 'Type of ref (branch or tag).'
    end
  end
end
