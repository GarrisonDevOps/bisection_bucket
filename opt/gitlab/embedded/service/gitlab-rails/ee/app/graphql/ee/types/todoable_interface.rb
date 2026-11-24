# frozen_string_literal: true

module EE
  module Types
    module TodoableInterface
      extend ActiveSupport::Concern

      class_methods do
        extend ::Gitlab::Utils::Override

        override :resolve_type
        def resolve_type(object, *)
          case object
          when Epic
            ::Types::EpicType
          when Vulnerability
            ::Types::VulnerabilityType
          when ::ComplianceManagement::Projects::ComplianceViolation
            ::Types::ComplianceManagement::Projects::ComplianceViolationType
          when ::Ai::DuoWorkflows::Workflow
            ::Types::Ai::DuoWorkflows::WorkflowType
          else
            super
          end
        end
      end
    end
  end
end
