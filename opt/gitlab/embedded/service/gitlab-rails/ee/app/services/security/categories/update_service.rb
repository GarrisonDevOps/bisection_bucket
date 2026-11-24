# frozen_string_literal: true

module Security
  module Categories
    class UpdateService < BaseService
      def initialize(category:, params:, current_user:)
        @category = category
        @params = params
        @current_user = current_user
      end

      def execute
        return UnauthorizedError unless permitted?
        return ServiceResponse.error(message: 'This category is not editable') unless editable?

        update_params = params.except(:namespace, :editable_state, :template_type, :multiple_selection)
        return error unless update_params.present? && category.update(update_params)

        changed_params = update_params.select { |key, _| category.saved_changes.key?(key.to_s) }
        create_audit_event(changed_params) if changed_params.any?
        success
      end

      attr_reader :category, :params, :current_user

      private

      def permitted?
        Ability.allowed?(current_user, :admin_security_attributes, category.namespace)
      end

      def editable?
        category&.editable_state == "editable"
      end

      def success
        ServiceResponse.success(payload: { category: category })
      end

      def error
        message = 'Failed to update security category'
        message += ": #{category.errors.full_messages.join(', ')}" if category.errors.present?
        ServiceResponse.error(message: message, payload: category.errors)
      end

      def create_audit_event(update_params)
        audit_context = {
          name: 'security_category_updated',
          author: current_user,
          scope: category.namespace,
          target: category,
          message: "Updated security category #{category.name}",
          additional_details: {
            organization_id: category.namespace.organization_id,
            category_name: category.name,
            updated_fields: update_params.keys
          }.merge(update_params)
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
