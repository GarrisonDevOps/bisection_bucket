# frozen_string_literal: true

module Mutations
  module ComplianceManagement
    module ComplianceFramework
      module ComplianceRequirements
        class Create < BaseMutation
          graphql_name 'CreateComplianceRequirement'

          authorize :admin_compliance_framework
          authorize_granular_token permissions: :create_compliance_requirement,
            boundary_argument: :compliance_framework_id, boundary: :namespace, boundary_type: :group

          field :requirement,
            Types::ComplianceManagement::ComplianceRequirementType,
            null: true,
            description: 'Created compliance requirement.'

          argument :compliance_framework_id, ::Types::GlobalIDType[::ComplianceManagement::Framework],
            required: true,
            description: 'Global ID of the compliance framework of the new requirement.'

          argument :params, Types::ComplianceManagement::ComplianceRequirementInputType,
            required: true,
            description: 'Parameters to update the compliance requirement with.'

          argument :controls,
            [::Types::ComplianceManagement::ComplianceRequirementsControlInputType],
            required: false,
            description: 'Controls to add to the compliance requirement.'

          def resolve(args)
            framework = authorized_find!(id: args[:compliance_framework_id])

            service = ::ComplianceManagement::ComplianceFramework::ComplianceRequirements::CreateService.new(
              framework: framework,
              params: args[:params].to_h,
              current_user: current_user,
              controls: args[:controls]
            ).execute

            service.success? ? success(service) : error(service)
          end

          private

          def success(service)
            { requirement: service.payload[:requirement], errors: [] }
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
