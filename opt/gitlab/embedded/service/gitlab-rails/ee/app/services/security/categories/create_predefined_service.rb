# frozen_string_literal: true

module Security
  module Categories
    class CreatePredefinedService < BaseService
      def initialize(namespace:, current_user:)
        @root_namespace = namespace&.root_ancestor
        @current_user = current_user
      end

      def execute
        return UnauthorizedError unless permitted?
        return ServiceResponse.success if has_categories?

        categories = Security::DefaultCategoriesHelper.default_categories.each do |category|
          category.namespace = root_namespace
          category.security_attributes.each do |security_attribute|
            security_attribute.namespace = root_namespace
          end
        end

        Security::Category.transaction do
          categories.each(&:save!)
        end

        ServiceResponse.success
      rescue ActiveRecord::ActiveRecordError => e
        ServiceResponse.error(message: "Failed to create default categories: #{e.message}")
      end

      private

      attr_reader :root_namespace, :current_user

      def permitted?
        Ability.allowed?(current_user, :admin_security_attributes, root_namespace)
      end

      def has_categories?
        Security::Category.by_namespace(root_namespace).exists?
      end
    end
  end
end
