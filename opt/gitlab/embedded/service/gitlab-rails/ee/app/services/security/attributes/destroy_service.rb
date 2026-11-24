# frozen_string_literal: true

module Security
  module Attributes
    class DestroyService < BaseService
      AUDIT_EVENT_NAME = 'security_attribute_deleted'

      def initialize(attribute:, current_user:)
        @attribute = attribute
        @current_user = current_user
      end

      def execute
        return UnauthorizedError unless permitted?

        return not_editable_error unless attribute.editable?

        deleted_attribute_gid = attribute.to_global_id

        if attribute.destroy
          create_audit_event
          success(deleted_attribute_gid)
        else
          deletion_failed_error("Failed to delete attribute")
        end
      rescue ActiveRecord::RecordNotDestroyed => e
        deletion_failed_error(e.message)
      end

      private

      attr_reader :attribute, :current_user

      def permitted?
        Ability.allowed?(current_user, :admin_security_attributes, attribute.security_category)
      end

      def success(deleted_attribute_gid)
        enqueue_project_associations_cleanup
        ServiceResponse.success(payload: { deleted_attribute_gid: deleted_attribute_gid })
      end

      def enqueue_project_associations_cleanup
        Security::Attributes::CleanupProjectToSecurityAttributeWorker.perform_async(attribute.id)
      end

      def error_response(message)
        ServiceResponse.error(message: message, payload: [message])
      end

      def not_editable_error
        error_response("Cannot delete non-editable attribute")
      end

      def deletion_failed_error(error_message)
        error_response("Failed to delete attributes: #{error_message}")
      end

      def create_audit_event
        root_namespace = attribute.security_category.namespace&.root_ancestor

        audit_context = {
          name: AUDIT_EVENT_NAME,
          author: current_user,
          scope: root_namespace,
          target: attribute,
          message: "Deleted security attribute #{attribute.name}",
          additional_details: {
            organization_id: root_namespace.organization_id,
            attribute_name: attribute.name,
            attribute_description: attribute.description,
            category_name: attribute.security_category.name
          }
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
