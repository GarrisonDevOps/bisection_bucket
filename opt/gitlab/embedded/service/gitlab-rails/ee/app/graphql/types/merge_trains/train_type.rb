# frozen_string_literal: true

module Types
  module MergeTrains
    class TrainType < BaseObject
      graphql_name 'MergeTrain'
      description 'Represents a set of cars/merge_requests queued for merging'

      connection_type_class Types::CountableConnectionType
      authorize :read_merge_train

      alias_method :merge_train, :object

      field :cars,
        Types::MergeTrains::CarType.connection_type,
        null: false,
        resolver: Resolvers::MergeTrains::CarsResolver,
        description: "Cars queued in the train.",
        experiment: { milestone: '17.1' }
      field :target_branch,
        GraphQL::Types::String,
        null: false,
        description: "Target branch of the car's merge request."
    end
  end
end
