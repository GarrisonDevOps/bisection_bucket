# frozen_string_literal: true

module ComplianceManagement
  module Frameworks
    class CreateFromTemplateService
      def initialize(user:, group:, template_id:, overrides: {})
        @user = user
        @group = group
        @template_id = template_id
        @overrides = overrides
      end

      def execute
        template = ::ComplianceManagement::Frameworks::TemplateRegistry.find(template_id)

        return ServiceResponse.error(message: 'Template not found') unless template

        json_payload = build_payload(template)

        ::ComplianceManagement::Frameworks::JsonImportService.new(
          user: user,
          group: group,
          json_payload: json_payload
        ).execute
      end

      private

      attr_reader :user, :group, :template_id, :overrides

      def build_payload(template)
        {
          name: overrides[:name] || template.name,
          description: overrides[:description] || template.description,
          color: overrides[:color] || template.color,
          default: overrides[:default],
          requirements: template.requirements,
          template_id: template.id,
          template_version: template.template_version
        }.compact
      end
    end
  end
end
