# frozen_string_literal: true

module EE
  module Mutations
    module WorkItems
      module BulkUpdate
        extend ActiveSupport::Concern

        prepended do
          argument :health_status_widget,
            ::Types::WorkItems::Widgets::HealthStatusInputType,
            required: false,
            description: 'Input for health status widget.',
            experiment: { milestone: '18.2' }

          argument :iteration_widget,
            ::Types::WorkItems::Widgets::IterationInputType,
            required: false,
            description: 'Input for iteration widget.',
            experiment: { milestone: '18.2' }

          argument :status_widget,
            ::Types::WorkItems::Widgets::StatusInputType,
            required: false,
            description: 'Input for status widget.',
            experiment: { milestone: '18.3' }
        end
      end
    end
  end
end
