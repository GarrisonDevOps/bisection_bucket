# frozen_string_literal: true

module Security
  module Categories
    class FindOrCreateService < BaseService
      def initialize(namespace:, current_user:, category_id: nil)
        @namespace = namespace&.root_ancestor
        @category_id = category_id
        @current_user = current_user
      end

      def execute
        return ServiceResponse.error(message: 'Namespace not found') unless namespace.present?
        return UnauthorizedError unless permitted?

        parsed_category = parse_category_id

        if parsed_category[:template_type].present?
          predefined_result = CreatePredefinedService.new(namespace: namespace, current_user: current_user).execute
          return predefined_result if predefined_result.error?
        end

        category = find_category(parsed_category[:category_id], parsed_category[:template_type])
        if category
          ServiceResponse.success(payload: { category: category })
        else
          ServiceResponse.error(message: 'Category not found')
        end
      end

      private

      attr_reader :category_id, :namespace, :current_user

      def parse_category_id
        valid_template_types = Enums::Security.categories_template_types.keys.map(&:to_s)

        return { category_id: nil, template_type: category_id } if valid_template_types.include?(category_id)

        { category_id: category_id, template_type: nil }
      end

      def find_category(parsed_category_id, parsed_template_type)
        if parsed_category_id
          # Scope the lookup to the boundary namespace so a category from another
          # namespace can never be resolved via a matching `namespace` argument.
          ::Security::Category.by_namespace(namespace).find_by_id(parsed_category_id)
        elsif parsed_template_type && namespace
          ::Security::Category.by_namespace_and_template_type(namespace.root_ancestor, parsed_template_type).first
        end
      end

      def permitted?
        Ability.allowed?(current_user, :admin_security_attributes, namespace)
      end
    end
  end
end
