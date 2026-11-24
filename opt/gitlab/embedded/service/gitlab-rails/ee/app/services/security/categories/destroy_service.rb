# frozen_string_literal: true

module Security
  module Categories
    class DestroyService < BaseService
      def initialize(category:, current_user:)
        @category = category
        @current_user = current_user
      end

      def execute
        return UnauthorizedError unless permitted?
        return not_editable_error unless category.editable?

        deleted_category_gid = category.to_global_id
        deleted_attributes_id_to_gid = category.security_attributes.not_deleted.to_h do |attribute|
          [attribute.id, attribute.to_global_id]
        end

        create_audit_event
        category.destroy
        success(deleted_category_gid, deleted_attributes_id_to_gid, category.id)
      rescue ActiveRecord::RecordNotDestroyed, ActiveRecord::StatementInvalid => e
        deletion_failed_error(e.message)
      end

      attr_reader :category, :current_user

      private

      def permitted?
        Ability.allowed?(current_user, :admin_security_attributes, category.namespace)
      end

      def success(deleted_category_gid, deleted_attributes_id_to_gid, category_id)
        enqueue_project_associations_cleanup(deleted_attributes_id_to_gid.keys, category_id)
        ServiceResponse.success(payload:
                                  {
                                    deleted_category_gid: deleted_category_gid,
                                    deleted_attributes_gid: deleted_attributes_id_to_gid.values
                                  })
      end

      def enqueue_project_associations_cleanup(attribute_ids, category_id)
        Security::Attributes::CleanupProjectToSecurityAttributeWorker.perform_async(attribute_ids, category_id)
      end

      def error_response(message)
        ServiceResponse.error(message: message, payload: [message])
      end

      def not_editable_error
        error_response("Cannot delete non-editable category")
      end

      def deletion_failed_error(error_message)
        error_response("Failed to delete category: #{error_message}")
      end

      def create_audit_event
        audit_context = {
          name: 'security_category_deleted',
          author: current_user,
          scope: category.namespace,
          target: category,
          message: "Deleted security category #{category.name}",
          additional_details: {
            organization_id: category.namespace.organization_id,
            category_name: category.name,
            category_description: category.description,
            attributes_count: category.security_attributes.count
          }
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
