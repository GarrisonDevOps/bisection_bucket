# frozen_string_literal: true

module EE
  module WorkItems
    module TypesFramework
      module SystemDefined
        module WidgetDefinition
          extend ActiveSupport::Concern
          extend ::Gitlab::Utils::Override

          prepended do
            include ::WorkItems::OrganizationLicenseCheck
          end

          WIDGETS_WITH_LICENSE = {
            'health_status' => :issuable_health_status,
            'iteration' => :iterations,
            'weight' => :issue_weights,
            'verification_status' => :requirements,
            'requirement_legacy' => :requirements,
            'test_reports' => :requirements,
            'progress' => :okrs,
            'color' => :epic_colors,
            'custom_fields' => :custom_fields,
            'vulnerabilities' => :security_dashboard,
            'status' => :work_item_status,
            'ai_session' => :ai_workflows,
            'agent_plan' => :ai_workflows,
            'decision_log' => :ai_workflows,
            'escalation_policy' => :escalation_policies
          }.freeze

          class_methods do
            extend ::Gitlab::Utils::Override

            override :widget_types
            def widget_types
              super + WIDGETS_WITH_LICENSE.keys
            end
          end

          override :work_item_type
          def work_item_type
            # rubocop:disable Gitlab/AvoidDirectWorkItemTypeUsage -- In this case we can not use the provider
            # as we don't have a namespace
            ::WorkItems::TypesFramework::SystemDefined::Type.find_by_id(work_item_type_id) ||
              ::WorkItems::TypesFramework::Custom::Type.find_by_id(work_item_type_id)
            # rubocop:enable Gitlab/AvoidDirectWorkItemTypeUsage
          end

          override :licensed?
          def licensed?(resource_parent)
            # Return true if the widget type doesn't have a license requirement.
            return super if WIDGETS_WITH_LICENSE[widget_type].nil?

            feature_available_for_resource?(resource_parent, WIDGETS_WITH_LICENSE[widget_type])
          end
        end
      end
    end
  end
end
