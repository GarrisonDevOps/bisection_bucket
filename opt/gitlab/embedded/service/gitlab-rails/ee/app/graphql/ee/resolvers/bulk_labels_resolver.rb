# frozen_string_literal: true

module EE
  module Resolvers
    module BulkLabelsResolver
      extend ::ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      private

      override :handle_bulk_loading_labels
      def handle_bulk_loading_labels
        object.issuing_parent.is_a?(::Group) ? bulk_load_group_work_item_labels : super
      end

      def bulk_load_group_work_item_labels
        object_to_load_from = object.is_a?(Epic) ? object.sync_object : object

        bulk_load_labels_for_object(object_to_load_from)
      end
    end
  end
end
