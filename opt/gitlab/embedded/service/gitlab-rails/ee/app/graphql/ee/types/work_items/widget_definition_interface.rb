# frozen_string_literal: true

module EE
  module Types
    module WorkItems
      module WidgetDefinitionInterface
        extend ActiveSupport::Concern

        EE_ORPHAN_TYPES = [
          ::Types::WorkItems::WidgetDefinitions::LabelsType,
          ::Types::WorkItems::WidgetDefinitions::WeightType,
          ::Types::WorkItems::WidgetDefinitions::CustomFieldsType,
          ::Types::WorkItems::WidgetDefinitions::StatusType,
          ::Types::WorkItems::WidgetDefinitions::ProgressType
        ].freeze

        EE_TYPE_MAPPING = {
          ::WorkItems::Widgets::Labels => ::Types::WorkItems::WidgetDefinitions::LabelsType,
          ::WorkItems::Widgets::Weight => ::Types::WorkItems::WidgetDefinitions::WeightType,
          ::WorkItems::Widgets::CustomFields => ::Types::WorkItems::WidgetDefinitions::CustomFieldsType,
          ::WorkItems::Widgets::Status => ::Types::WorkItems::WidgetDefinitions::StatusType,
          ::WorkItems::Widgets::Progress => ::Types::WorkItems::WidgetDefinitions::ProgressType
        }.freeze

        class_methods do
          extend ::Gitlab::Utils::Override

          override :resolve_type
          def resolve_type(object, context)
            EE_TYPE_MAPPING[object.widget_class] || super
          end
        end

        prepended do
          orphan_types(*ce_orphan_types, *EE_ORPHAN_TYPES)
        end
      end
    end
  end
end
