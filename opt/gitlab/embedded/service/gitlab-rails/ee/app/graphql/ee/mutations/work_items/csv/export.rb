# frozen_string_literal: true

module EE
  module Mutations
    module WorkItems
      module CSV
        module Export
          extend ActiveSupport::Concern
          extend ::Gitlab::Utils::Override

          include ::WorkItems::IterationArgumentHelpers

          prepended do
            argument :health_status_filter, ::Types::HealthStatusFilterEnum,
              as: :health_status,
              required: false,
              description: 'Health status of the work items, "none" and "any" values are supported.',
              experiment: { milestone: '18.2' }

            argument :iteration_id, [::GraphQL::Types::ID, { null: true }],
              required: false,
              description: 'List of iteration Global IDs applied to the work items.',
              experiment: { milestone: '18.2' }
            argument :iteration_wildcard_id, ::Types::IterationWildcardIdEnum,
              required: false,
              description: 'Filter by iteration ID wildcard.',
              experiment: { milestone: '18.2' }
            argument :iteration_cadence_id, [::Types::GlobalIDType[::Iterations::Cadence]],
              required: false,
              description: 'Filter by a list of iteration cadence IDs.',
              experiment: { milestone: '18.2' }

            argument :weight, GraphQL::Types::String,
              required: false,
              description: 'Weight applied to the work item, "none" and "any" values are supported.',
              experiment: { milestone: '18.2' }
            argument :weight_wildcard_id, ::Types::WeightWildcardIdEnum,
              required: false,
              description: 'Filter by weight ID wildcard. Incompatible with weight.',
              experiment: { milestone: '18.2' }
            argument :status, ::Types::WorkItems::Widgets::StatusFilterInputType,
              required: false,
              description: 'Filter by status.',
              experiment: { milestone: '18.7' }

            validates mutually_exclusive: [:weight, :weight_wildcard_id]
            validates mutually_exclusive: [:iteration_id, :iteration_wildcard_id]
          end

          private

          override :prepare_finder_params
          def prepare_finder_params(args)
            params = super

            rewrite_param_name(params, :weight_wildcard_id, :weight)

            params[:iteration_id] = iteration_ids_from_args(args) if args[:iteration_id].present?

            params[:not] = args[:not].to_h if args[:not]
            params[:not][:iteration_id] = iteration_ids_from_args(args[:not]) if args.dig(:not, :iteration_id).present?

            if args[:iteration_cadence_id].present?
              params[:iteration_cadence_id] = iteration_cadence_ids_from_args(args)
            end

            params[:status] = args[:status].to_h if args[:status].present?

            rewrite_param_name(params, :iteration_wildcard_id, :iteration_id)
            params
          end
        end
      end
    end
  end
end
