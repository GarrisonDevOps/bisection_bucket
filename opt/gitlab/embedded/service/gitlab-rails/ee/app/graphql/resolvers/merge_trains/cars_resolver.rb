# frozen_string_literal: true

module Resolvers
  module MergeTrains
    class CarsResolver < BaseResolver
      include LooksAhead

      type ::Types::MergeTrains::CarType.connection_type, null: true

      argument :activity_status,
        ::Types::MergeTrains::TrainStatusEnum,
        required: true,
        default_value: 'active',
        description: 'Filter by the high-level status of the cars. Defaults to ACTIVE.'

      alias_method :merge_train, :object

      before_connection_authorization do |cars, _|
        ActiveRecord::Associations::Preloader.new(records: cars, associations: :target_project).call
      end

      def resolve_with_lookahead(activity_status:)
        BatchLoader::GraphQL.for([merge_train.project.id, merge_train.target_branch]).batch do |tuples, loader|
          tuples.each do |tuple|
            case activity_status
            when 'active'
              result = merge_train.all_active_cars_indexed
            when 'completed'
              result = merge_train.completed_cars
            end

            loader.call(tuple, apply_lookahead(result))
          end
        end
      end

      def preloads
        {
          merge_request: [{ merge_request: [:source_project, :target_project, :author] }],
          pipeline: [{ pipeline: [:user, :project] }]
        }
      end
    end
  end
end
