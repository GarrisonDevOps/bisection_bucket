# frozen_string_literal: true

module Mutations
  module ComplianceManagement
    module ComplianceFramework
      module ComplianceRequirementsControls
        class Create < BaseMutation
          graphql_name 'CreateComplianceRequirementsControl'

          authorize :admin_compliance_framework
          authorize_granular_token permissions: :create_compliance_requirements_control,
            boundary_argument: :compliance_requirement_id, boundary: :namespace, boundary_type: :group

          field :requirements_control,
            Types::ComplianceManagement::ComplianceRequirementsControlType,
            null: true,
            description: 'Created compliance requirements control.'

          argument :compliance_requirement_id,
            ::Types::GlobalIDType[::ComplianceManagement::ComplianceFramework::ComplianceRequirement],
            required: true,
            description: 'Global ID of the compliance requirement of the new control.'

          argument :params, Types::ComplianceManagement::ComplianceRequirementsControlInputType,
            required: true,
            description: 'Parameters to create the compliance requirement control.'

          def resolve(args)
            requirement = authorized_find!(id: args[:compliance_requirement_id])

            service = ::ComplianceManagement::ComplianceFramework::ComplianceRequirementsControls::CreateService.new(
              requirement: requirement,
              params: args[:params].to_h,
              current_user: current_user
            ).execute

            service.success? ? success(service) : error(service)
          end

          private

          def success(service)
            { requirements_control: service.payload[:control], errors: [] }
          end

          def error(service)
            errors = [service.message]
            model_errors = service.payload.try(:full_messages).to_a

            { errors: (errors + model_errors).flatten }
          end
        end
      end
    end
  end
end
