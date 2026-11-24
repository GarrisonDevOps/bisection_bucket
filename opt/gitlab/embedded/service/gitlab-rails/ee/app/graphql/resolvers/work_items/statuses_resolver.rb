# frozen_string_literal: true

module Resolvers
  module WorkItems
    class StatusesResolver < Resolvers::WorkItems::BaseResolver
      type Types::WorkItems::StatusType.connection_type, null: true
      authorize :read_work_item_status

      alias_method :namespace, :object

      MAX_IDS = ::WorkItems::Statuses::Custom::Status::MAX_STATUSES_PER_NAMESPACE

      argument :ids, [::Types::GlobalIDType[::WorkItems::Statuses::Status]],
        required: false,
        description: "Filter statuses by ID. A max of #{MAX_IDS} can be provided.",
        validates: { length: { maximum: MAX_IDS } },
        # System-defined statuses are matched in memory rather than in SQL, where "1" != 1,
        # so the IDs have to be Integers.
        prepare: ->(ids, _ctx) { ids&.map { |id| id.model_id.to_i } }

      def resolve(ids: nil)
        return unless work_item_status_licensed_feature_available?

        namespace.statuses(ids: ids)
      end

      private

      def root_ancestor
        namespace.root_ancestor
      end
    end
  end
end
