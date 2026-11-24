# frozen_string_literal: true

module Mutations
  module MergeTrains
    module Cars
      class Delete < BaseMutation
        graphql_name 'MergeTrainsDeleteCar'
        authorize :delete_merge_train_car
        authorize_granular_token permissions: :delete_merge_train_car,
          boundary_argument: :car_id, boundary: :project, boundary_type: :project

        argument :car_id,
          ::Types::GlobalIDType[::MergeTrains::Car],
          required: true,
          description: 'Global ID of the car.'

        attr_reader :car

        delegate :project, :merge_request, to: :car

        def resolve(car_id:)
          @car = authorized_find!(id: car_id)

          ensure_feature_available!
          response = ::AutoMerge::MergeTrainService.new(project, current_user).cancel(merge_request)
          errors = response[:status] == :error ? [response[:message]] : []

          { errors: errors }
        end

        private

        def ensure_feature_available!
          return if merge_trains_available?

          raise_resource_not_available_error!
        end

        def merge_trains_available?
          project.licensed_feature_available?(:merge_trains)
        end
      end
    end
  end
end
