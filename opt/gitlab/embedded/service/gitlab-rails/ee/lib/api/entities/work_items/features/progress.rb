# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class Progress < Grape::Entity
          # Progress is calculated by WorkItems::Callbacks::Progress and rolled up to the parent
          # by WorkItems::UpdateParentObjectivesProgressWorker.
          expose :progress,
            documentation: {
              type: 'Integer', example: 65,
              desc: 'Progress as a percentage from 0 to 100, calculated from where `current_value` lies between ' \
                "`start_value` and `end_value`. When a child work item's progress changes, it is set to the average " \
                'progress of all child work items, counting children without progress as 0. Null if progress ' \
                'was never set.'
            },
            expose_nil: true

          expose :updated_at,
            documentation: {
              type: 'DateTime', example: '2024-02-12T09:45:00Z',
              desc: 'Time the progress or its values were last changed. Null if progress was never set.'
            },
            expose_nil: true

          # The value columns are floats, but every writer accepts only integers, so the
          # three values are exposed as integers, as the GraphQL Int fields return them.
          with_options(format_with: ->(value) { value&.to_i }, expose_nil: true) do
            expose :current_value,
              documentation: {
                type: 'Integer', example: 13,
                desc: 'Current value. If it is outside the range from `start_value` to `end_value`, progress is ' \
                  'capped at 0 or 100. Null if progress was never set.'
              }

            expose :start_value,
              documentation: {
                type: 'Integer', example: 0,
                desc: 'Value at which progress is 0. Defaults to 0. Null if progress was never set.'
              }

            expose :end_value,
              documentation: {
                type: 'Integer', example: 20,
                desc: 'Value at which progress is 100. Defaults to 100. Null if progress was never set.'
              }
          end
        end
      end
    end
  end
end
