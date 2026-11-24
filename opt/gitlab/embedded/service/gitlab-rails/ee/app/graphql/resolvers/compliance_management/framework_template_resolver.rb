# frozen_string_literal: true

module Resolvers
  module ComplianceManagement
    class FrameworkTemplateResolver < BaseResolver
      type [::Types::ComplianceManagement::ComplianceFrameworkTemplateType], null: true

      argument :id, ::Types::GlobalIDType[::ComplianceManagement::Frameworks::TemplateRegistry::Template],
        required: false,
        description: 'Filter by template ID.'

      def resolve(id: nil)
        raise_resource_not_available_error! unless current_user

        if id
          template = ::ComplianceManagement::Frameworks::TemplateRegistry.find(id.model_id)
          template ? [template] : []
        else
          ::ComplianceManagement::Frameworks::TemplateRegistry.all
        end
      end
    end
  end
end
