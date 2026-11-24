# frozen_string_literal: true

module Security
  module Attributes
    class CreateService < BaseService
      AUDIT_EVENT_NAME = 'security_attribute_created'

      def initialize(category:, namespace:, params:, current_user:)
        @category = category
        @root_namespace = namespace&.root_ancestor
        @params = params
        @current_user = current_user
        @attributes = []
      end

      def execute
        return UnauthorizedError unless permitted?
        return non_editable unless category.editable?

        @attributes = params[:attributes].map do |attribute_params|
          category.security_attributes.build(
            namespace: root_namespace,
            name: attribute_params[:name],
            description: attribute_params[:description],
            color: attribute_params[:color],
            editable_state: :editable
          )
        end

        return error(attributes.select(&:invalid?)) if attributes.any?(&:invalid?) || !category.valid?

        if category.save # Saving the category saves its attributes
          create_audit_events
          success
        else
          error
        end
      end

      attr_reader :category, :root_namespace, :params, :current_user, :attributes

      private

      def permitted?
        Ability.allowed?(current_user, :admin_security_attributes, category)
      end

      def success
        ServiceResponse.success(payload: { attributes: attributes })
      end

      def non_editable
        ServiceResponse.error(message: "You can not edit this category's attributes.")
      end

      def error(failed_attributes = attributes)
        errors = failed_attributes.map(&:errors).flat_map(&:full_messages).uniq + category.errors.full_messages
        message = "Failed to create security attributes"
        message += ": #{errors.join(', ')}" if errors.any?
        ServiceResponse.error(message: message, payload: errors)
      end

      def create_audit_events
        return if attributes.empty?

        ::Gitlab::Audit::Auditor.audit(created_audit_context) do
          attributes.each do |attribute|
            event = AuditEvents::BuildService.new(
              author: current_user,
              scope: root_namespace,
              target: attribute,
              created_at: Time.current,
              message: "Created security attribute #{attribute.name}",
              additional_details: {
                event_name: AUDIT_EVENT_NAME,
                organization_id: root_namespace.organization_id,
                attribute_name: attribute.name,
                attribute_description: attribute.description,
                attribute_color: attribute.color.to_s,
                category_name: category.name
              }
            ).execute

            ::Gitlab::Audit::EventQueue.push(event)
          end
        end
      end

      def created_audit_context
        {
          author: current_user,
          scope: root_namespace,
          target: root_namespace,
          name: AUDIT_EVENT_NAME
        }
      end
    end
  end
end
