# frozen_string_literal: true

module Types
  module MergeTrains
    class CarStatusEnum < BaseEnum
      graphql_name 'CarStatus'
      description "Status of a merge train's car"

      ::MergeTrains::Car.state_machine.states.each do |state|
        value state.name.to_s.upcase, value: state.value, description: "Car's status: #{state.name}"
      end
    end
  end
end
