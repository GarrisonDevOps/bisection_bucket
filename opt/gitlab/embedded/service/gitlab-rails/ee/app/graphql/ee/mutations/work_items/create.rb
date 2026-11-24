# frozen_string_literal: true

module EE
  module Mutations
    module WorkItems
      module Create
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        prepended do
          argument :weight_widget,
            ::Types::WorkItems::Widgets::WeightInputType,
            required: false,
            description: 'Input for weight widget.'

          argument :health_status_widget,
            ::Types::WorkItems::Widgets::HealthStatusInputType,
            required: false,
            description: 'Input for health status widget.'

          argument :iteration_widget,
            ::Types::WorkItems::Widgets::IterationInputType,
            required: false,
            description: 'Iteration widget of the work item.'

          argument :color_widget, ::Types::WorkItems::Widgets::ColorInputType,
            required: false,
            description: 'Input for color widget.'

          argument :custom_fields_widget, [::Types::WorkItems::Widgets::CustomFieldValueInputType],
            required: false,
            description: 'Input for custom fields widget.',
            experiment: { milestone: '17.10' }

          argument :vulnerability_id, ::Types::GlobalIDType[::Vulnerability], # rubocop:disable Graphql/ForbiddenLoadsArgument -- pre-existing code; removing `loads:` would be a breaking change
            loads: ::Types::VulnerabilityType,
            required: false,
            description: 'Input for linking an existing vulnerability to created work item.',
            experiment: { milestone: '17.9' }

          argument :status_widget, ::Types::WorkItems::Widgets::StatusInputType,
            required: false,
            description: 'Input for status widget.',
            experiment: { milestone: '17.11' }

          argument :agent_plan_widget, ::Types::WorkItems::Widgets::AgentPlanInputType,
            required: false,
            description: 'Input for agent plan widget.',
            experiment: { milestone: '19.0' }
        end

        override :prepare_widget_params
        def prepare_widget_params(widget_params, type, container)
          result = super

          return result unless context[:mcp_tool] == :create_work_item
          return result unless ::Feature.enabled?(:workplan, container.root_ancestor)
          return result unless type.widget_classes(container).include?(::WorkItems::Widgets::AgentPlan)

          agent_plan_params = result.fetch(:agent_plan_widget, {})
          result.merge(agent_plan_widget: agent_plan_params.merge(ai_planning_enabled: true))
        end

        override :resolve
        def resolve(project_path: nil, namespace_path: nil, vulnerability: nil, **attributes)
          result = super(project_path: project_path, namespace_path: namespace_path, **attributes)
          work_item = result[:work_item]
          errors = result[:errors]

          return result if errors.any? || vulnerability.blank?

          result = VulnerabilityIssueLinks::CreateService.new(
            current_user, vulnerability, work_item, link_type: Vulnerabilities::IssueLink.link_types[:created]
          ).execute

          {
            work_item: work_item,
            errors: result.errors
          }
        end

        override :check_feature_available!
        def check_feature_available!(container, type, params)
          check_custom_type_feature!(container, type)

          return super unless container.is_a?(Project) && type.epic?

          raise_resource_not_available_error! unless Ability.allowed?(current_user, :create_epic, container)
        end

        def check_custom_type_feature!(container, type)
          return unless type.try(:non_converted_custom_type?)

          unless container.is_a?(Project) || container.is_a?(Namespaces::ProjectNamespace)
            raise ::Gitlab::Graphql::Errors::ArgumentError, 'Custom types can only be created in projects'
          end

          return if container.licensed_feature_available?(:configurable_work_item_types)

          raise_resource_not_available_error! 'Configurable work item types are not available'
        end
      end
    end
  end
end
