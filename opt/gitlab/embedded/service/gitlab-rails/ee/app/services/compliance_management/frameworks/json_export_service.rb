# frozen_string_literal: true

module ComplianceManagement
  module Frameworks
    class JsonExportService
      def initialize(user:, group:, framework:)
        @user = user
        @group = group
        @framework = framework
      end

      def execute
        return ServiceResponse.error(message: 'namespace must be a group') unless group.is_a?(Group)
        return ServiceResponse.error(message: "Access to group denied for user with ID: #{user.id}") unless allowed?

        begin
          success
        rescue StandardError => e
          Gitlab::ErrorTracking.track_exception(e, group_id: group.id, user_id: user.id, framework_id: framework.id)
          error
        end
      end

      private

      attr_reader :user, :group, :framework

      def allowed?
        Ability.allowed?(user, :read_compliance_dashboard, group)
      end

      def success
        ServiceResponse.success(payload:)
      end

      def error
        ServiceResponse.error(message: _('Failed to export framework'))
      end

      def payload
        {
          name: framework.name,
          description: framework.description,
          color: framework.color,
          requirements: framework.compliance_requirements.map do |requirement|
            {
              name: requirement.name,
              description: requirement.description,
              controls: requirement.compliance_requirements_controls.map do |control|
                {
                  name: control.name,
                  control_type: control.control_type,
                  expression: control.expression_as_hash
                }
              end
            }
          end
        }.to_json
      end
    end
  end
end
