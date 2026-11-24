# frozen_string_literal: true

module WorkItems
  module TypesFramework
    class VisibilityUpdateService
      def initialize(namespace:, work_item_type_id:, enabled:, propagate: false)
        @namespace = namespace
        @work_item_type_id = work_item_type_id
        @enabled = enabled
        @propagate = propagate
      end

      def execute
        # rubocop:disable CodeReuse/ActiveRecord -- no model wrapper adds value here
        visibility = Visibility.find_or_initialize_by(
          namespace_id: @namespace.id,
          work_item_type_id: @work_item_type_id
        )
        # rubocop:enable CodeReuse/ActiveRecord
        visibility.enabled = @enabled
        visibility.propagate = @propagate

        return ServiceResponse.error(message: visibility.errors.full_messages.to_sentence) unless visibility.save

        delete_conflicting_descendants if @propagate

        ServiceResponse.success(payload: { visibility: visibility })
      end

      private

      def delete_conflicting_descendants
        # Runs synchronously: scoped to a single work_item_type_id via a dedicated index
        # and the table is sparse (one row per namespace+type pair, only via explicit admin
        # action). Both conditions together keep the affected row count low in practice.
        # rubocop:disable CodeReuse/ActiveRecord -- bulk delete only used here
        Visibility
          .where(work_item_type_id: @work_item_type_id)
          .where(namespace_id: @namespace.self_and_descendant_ids(skope: Namespace).id_not_in(@namespace.id))
          .delete_all
        # rubocop:enable CodeReuse/ActiveRecord
      end
    end
  end
end
