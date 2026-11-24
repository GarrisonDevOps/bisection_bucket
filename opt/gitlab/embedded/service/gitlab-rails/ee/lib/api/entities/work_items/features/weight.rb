# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class Weight < Grape::Entity
          expose :weight,
            documentation: { type: 'Integer', example: 3, desc: 'Weight of the work item. Null if not set.' },
            expose_nil: true

          # Rolled-up weights are calculated by WorkItems::WeightsSource.upsert_rolled_up_weights_for.
          expose :rolled_up_weight,
            documentation: {
              type: 'Integer', example: 8,
              desc: 'Total weight of the child work items, open and closed. A child that has its own rolled-up ' \
                'weight counts with that instead of its own weight. ' \
                'Null if no child has a weight or the rollup has not been calculated.'
            },
            expose_nil: true

          expose :rolled_up_completed_weight,
            documentation: {
              type: 'Integer', example: 5,
              desc: 'Part of `rolled_up_weight` that is completed. A closed child counts with its rolled-up weight, ' \
                'or its own weight if it has none. An open child counts with its own `rolled_up_completed_weight`. ' \
                '0 if nothing is completed. Null if the rollup has not been calculated.'
            },
            expose_nil: true
        end
      end
    end
  end
end
