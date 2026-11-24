# frozen_string_literal: true

module EE
  module Groups
    module OpenWorkItemsCountService
      extend ::Gitlab::Utils::Override

      private

      override :relation_for_count
      def relation_for_count
        excluded_types = non_filterable_type_ids(group)
        return super if excluded_types.blank?

        super.without_work_item_type_ids(excluded_types)
      end

      def non_filterable_type_ids(namespace)
        ::WorkItems::TypesFramework::Provider.new(namespace).all
          .reject(&:filterable_list_view?)
          .map(&:persistable_id)
      end
    end
  end
end
