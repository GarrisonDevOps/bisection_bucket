# frozen_string_literal: true

module EE
  module Types
    module WorkItems
      module WidgetInterface
        extend ActiveSupport::Concern

        class_methods do
          extend ::Gitlab::Utils::Override

          override :type_mappings
          def type_mappings
            super.merge(EE_TYPE_MAPPINGS)
          end
        end

        prepended do
          EE_TYPE_MAPPINGS = {
            ::WorkItems::Widgets::Weight => ::Types::WorkItems::Widgets::WeightType,
            ::WorkItems::Widgets::VerificationStatus => ::Types::WorkItems::Widgets::VerificationStatusType,
            ::WorkItems::Widgets::Iteration => ::Types::WorkItems::Widgets::IterationType,
            ::WorkItems::Widgets::HealthStatus => ::Types::WorkItems::Widgets::HealthStatusType,
            ::WorkItems::Widgets::Progress => ::Types::WorkItems::Widgets::ProgressType,
            ::WorkItems::Widgets::RequirementLegacy => ::Types::WorkItems::Widgets::RequirementLegacyType,
            ::WorkItems::Widgets::TestReports => ::Types::WorkItems::Widgets::TestReportsType,
            ::WorkItems::Widgets::Color => ::Types::WorkItems::Widgets::ColorType,
            ::WorkItems::Widgets::CustomFields => ::Types::WorkItems::Widgets::CustomFieldsType,
            ::WorkItems::Widgets::Vulnerabilities => ::Types::WorkItems::Widgets::VulnerabilitiesType,
            ::WorkItems::Widgets::Status => ::Types::WorkItems::Widgets::StatusType,
            ::WorkItems::Widgets::AiSession => ::Types::WorkItems::Widgets::AiSessionType,
            ::WorkItems::Widgets::AgentPlan => ::Types::WorkItems::Widgets::AgentPlanType,
            ::WorkItems::Widgets::DecisionLog => ::Types::WorkItems::Widgets::DecisionLogType,
            ::WorkItems::Widgets::EscalationPolicy => ::Types::WorkItems::Widgets::EscalationPolicyType
          }.freeze

          orphan_types(*type_mappings.values)
        end
      end
    end
  end
end
