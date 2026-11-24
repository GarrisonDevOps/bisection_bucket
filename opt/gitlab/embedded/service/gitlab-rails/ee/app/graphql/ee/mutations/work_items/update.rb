# frozen_string_literal: true

module EE
  module Mutations
    module WorkItems
      module Update
        extend ActiveSupport::Concern

        prepended do
          argument :iteration_widget, ::Types::WorkItems::Widgets::IterationInputType,
            required: false,
            description: 'Input for iteration widget.'

          argument :weight_widget, ::Types::WorkItems::Widgets::WeightInputType,
            required: false,
            description: 'Input for weight widget.'

          argument :progress_widget, ::Types::WorkItems::Widgets::ProgressInputType,
            required: false,
            description: 'Input for progress widget.'

          argument :verification_status_widget, ::Types::WorkItems::Widgets::VerificationStatusInputType,
            required: false,
            description: 'Input for verification status widget.'

          argument :health_status_widget, ::Types::WorkItems::Widgets::HealthStatusInputType,
            required: false,
            description: 'Input for health status widget.'

          argument :color_widget, ::Types::WorkItems::Widgets::ColorInputType,
            required: false,
            description: 'Input for color widget.'

          argument :custom_fields_widget, [::Types::WorkItems::Widgets::CustomFieldValueInputType],
            required: false,
            description: 'Input for custom fields widget.',
            experiment: { milestone: '17.10' }

          argument :status_widget, ::Types::WorkItems::Widgets::StatusInputType,
            required: false,
            description: 'Input for status widget.',
            experiment: { milestone: '17.11' }

          argument :agent_plan_widget, ::Types::WorkItems::Widgets::AgentPlanInputType,
            required: false,
            description: 'Input for agent plan widget.',
            experiment: { milestone: '19.0' }
        end
      end
    end
  end
end
