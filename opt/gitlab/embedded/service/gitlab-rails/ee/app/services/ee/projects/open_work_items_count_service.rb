# frozen_string_literal: true

module EE
  module Projects
    module OpenWorkItemsCountService
      extend ::Gitlab::Utils::Override

      override :relation_for_count
      def relation_for_count
        excluded_types = non_filterable_type_ids(project)
        return super if excluded_types.blank?

        super.without_work_item_type_ids(excluded_types)
      end

      private

      def non_filterable_type_ids(resource_parent)
        ::WorkItems::TypesFramework::Provider.new(resource_parent).all
          .reject(&:filterable_list_view?)
          .map(&:persistable_id)
      end
    end
  end
end
