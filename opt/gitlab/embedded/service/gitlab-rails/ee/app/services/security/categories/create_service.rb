# frozen_string_literal: true

module Security
  module Categories
    class CreateService < BaseService
      def initialize(namespace:, params:, current_user:)
        @root_namespace = namespace&.root_ancestor
        @params = params
        @current_user = current_user
        @category = Security::Category.new
      end

      def execute
        precondition_error = check_preconditions
        return precondition_error if precondition_error

        category.assign_attributes(
          namespace: root_namespace,
          name: params[:name],
          description: params[:description],
          editable_state: params[:editable_state] || :editable,
          template_type: params[:template_type],
          multiple_selection: params[:multiple_selection] || false
        )
        return error unless category.save

        create_audit_event
        success
      end

      attr_reader :root_namespace, :params, :current_user, :category

      private

      def check_preconditions
        return UnauthorizedError unless permitted?
        return error(categories_limit_error_message) if categories_limit_reached?

        error if predefined_service_failed?
      end

      def permitted?
        Ability.allowed?(current_user, :admin_security_attributes, root_namespace)
      end

      def predefined_service_failed?
        CreatePredefinedService.new(namespace: root_namespace, current_user: current_user).execute.error?
      end

      def categories_limit_reached?
        Security::Category.by_namespace(root_namespace).count >= Security::Category::MAX_CATEGORIES_PER_NAMESPACE
      end

      def categories_limit_error_message
        "Namespace cannot have more than #{Security::Category::MAX_CATEGORIES_PER_NAMESPACE} categories"
      end

      def success
        ServiceResponse.success(payload: { category: category })
      end

      def error(message = nil)
        ServiceResponse.error(message: message || _('Failed to create security category'), payload: category.errors)
      end

      def create_audit_event
        audit_context = {
          name: 'security_category_created',
          author: current_user,
          scope: root_namespace,
          target: category,
          message: "Created security category #{category.name}",
          additional_details: {
            organization_id: root_namespace.organization_id,
            category_name: category.name,
            category_description: category.description,
            multiple_selection: category.multiple_selection,
            template_type: category.template_type
          }
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      end
    end
  end
end
