# frozen_string_literal: true

module EE
  module Resolvers
    module UserDiscussionsCountResolver # rubocop:disable Gitlab/BoundedContexts -- Needed for override, to be removed after epics migration to work items
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      override :load_discussions_counts
      def load_discussions_counts
        return super unless unified_notes_count_for?(object)

        batch_object = [object.id, object&.sync_object&.id]

        BatchLoader::GraphQL.for(batch_object).batch do |ids, loader, _args|
          object_counts = ::Note.count_for_collection(
            ids.flat_map(&:first), object.class.base_class.name, 'COUNT(DISTINCT discussion_id) as count'
          ).index_by(&:noteable_id)

          sync_object_counts = ::Note.count_for_collection(
            ids.flat_map(&:second), object.sync_object.class.base_class.name, 'COUNT(DISTINCT discussion_id) as count'
          ).index_by(&:noteable_id)

          ids.each do |ids_pair|
            counts = object_counts[ids_pair.first]&.count.to_i
            sync_counts = sync_object_counts[ids_pair.second]&.count.to_i

            loader.call(ids_pair, counts + sync_counts)
          end
        end
      end

      def unified_notes_count_for?(object)
        object.issuing_parent.is_a?(::Group) && object.try(:sync_object).present?
      end
    end
  end
end
