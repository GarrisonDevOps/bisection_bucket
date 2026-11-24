# frozen_string_literal: true

module Resolvers
  module Security
    class CategoryResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type Types::Security::CategoryType.connection_type, null: true

      authorize :read_security_attribute

      description 'Resolves security categories for a group.'

      alias_method :group, :object

      def resolve
        authorize!(object)
        return [] unless root_ancestor

        existing_categories = ::Security::Category.by_namespace(root_ancestor).preload_not_deleted_attributes
        return existing_categories if existing_categories.any?

        default_categories
      end

      private

      def root_ancestor
        @root_ancestor ||= group.root_ancestor
      end

      def default_categories
        ::Security::DefaultCategoriesHelper.default_categories.tap do |categories|
          # Set the namespace_id for each category and its attributes
          categories.each do |category|
            category.namespace_id = root_ancestor.id
            category.security_attributes.each do |attribute|
              attribute.namespace_id = root_ancestor.id
            end
          end
        end
      end
    end
  end
end
