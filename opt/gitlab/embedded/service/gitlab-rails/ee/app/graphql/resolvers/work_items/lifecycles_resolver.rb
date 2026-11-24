# frozen_string_literal: true

module Resolvers
  module WorkItems
    class LifecyclesResolver < Resolvers::WorkItems::BaseResolver
      include ::WorkItems::Lifecycles::LookAheadPreloads

      type Types::WorkItems::LifecycleType.connection_type, null: true
      authorize :read_work_item_lifecycle

      alias_method :namespace, :object

      # Only apply preloading to custom lifecycles (ActiveRecord model)
      # Return system-defined lifecycles (Fixed model) as is
      def resolve_with_lookahead
        return unless work_item_status_licensed_feature_available?

        context[:namespace] = namespace
        lifecycles = root_ancestor.lifecycles

        lifecycles.is_a?(ActiveRecord::Relation) ? apply_lookahead(lifecycles) : lifecycles
      end

      private

      def root_ancestor
        namespace.root_ancestor
      end
    end
  end
end
