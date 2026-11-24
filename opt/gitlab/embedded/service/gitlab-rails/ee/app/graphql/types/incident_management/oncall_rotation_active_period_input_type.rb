# frozen_string_literal: true

module Types
  module IncidentManagement
    class OncallRotationActivePeriodInputType < BaseInputObject
      graphql_name 'OncallRotationActivePeriodInputType'
      description 'Active period time range for on-call rotation'

      argument :start_time, GraphQL::Types::String,
        required: true,
        description: 'Start of the rotation active period in 24 hour format. For example, "18:30".'

      argument :end_time, GraphQL::Types::String,
        required: true,
        description: 'End of the rotation active period in 24 hour format. For example, "18:30".'
    end
  end
end
