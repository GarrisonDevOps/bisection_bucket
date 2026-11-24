# frozen_string_literal: true

module Security
  module Attributes
    class UpdateService < BaseService
      AUDIT_EVENT_NAME = 'security_attribute_updated'

      def initialize(attribute:, params:, current_user:)
        @attribute = attribute
        @root_namespace = attribute.namespace&.root_ancestor
        @params = params
        @current_user = current_user
      end

      def execute
        return UnauthorizedError unless permitted?
        return ServiceResponse.error(message: 'Cannot update non editable attribute') unless attribute.editable?

        attribute.assign_attributes(params.slice(:name, :description, :color))

        if attribute.save
          create_audit_event if attribute.saved_changes.any?
          success
        else
          error
        end
      end

      attr_reader :attribute, :root_namespace, :params, :current_user

      private

      def permitted?
        Ability.allowed?(current_user, :admin_security_attributes, attribute.security_category)
      end

      def success
        ServiceResponse.success(payload: { attribute: attribute })
      end

      def error
        errors = attribute.errors.full_messages
        message = "Failed to update security attribute"
        message += ": #{errors.join(', ')}" if errors.any?
        ServiceResponse.error(message: message, payload: errors)
      end

      def create_audit_event
        audit_context = {
          name: AUDIT_EVENT_NAME,
          author: current_user,
          scope: root_namespace,
          target: attribute,
          message: "Updated security attribute #{attribute.name}",
          additional_details: {
            organization_id: root_namespace.organization_id,
            attribute_name: attribute.name,
            attribute_description: attribute.description,
            attribute_color: attribute.color.to_s,
            category_name: attribute.security_category.name,
            previous_values: {
              name: attribute.name_previously_was,
              description: attribute.description_previously_was,
              color: attribute.color_previously_was.to_s
            }
          }
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
