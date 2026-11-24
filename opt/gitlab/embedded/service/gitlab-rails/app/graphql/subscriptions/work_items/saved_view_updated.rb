# frozen_string_literal: true

module Subscriptions
  module WorkItems
    class SavedViewUpdated < BaseSubscription
      include Gitlab::Graphql::Laziness

      payload_type Types::WorkItems::SavedViews::SavedViewType

      rate_limit :work_item_saved_view_broadcast,
        scope: ->(args, _saved_view) { { saved_view: args[:saved_view_id].model_id } }

      argument :saved_view_id, ::Types::GlobalIDType[::WorkItems::SavedViews::SavedView],
        required: true,
        description: 'ID of the saved view.'

      # Re-runs on every delivery, so a subscriber who loses access (for example, the author makes the view private)
      # is unsubscribed before the next payload resolves.
      def authorized?(saved_view_id:)
        authorize_object_or_gid!(:read_saved_view, gid: saved_view_id)
      end
    end
  end
end
