# frozen_string_literal: true

module Gitlab
  module Graphql
    module Loaders
      module Ai
        class FlowSchedulesLoader < LazyRelationLoader
          self.model = ::Ai::FlowTrigger
          self.association = :flow_schedules

          def relation(**)
            base_relation.preload_project_route
          end
        end
      end
    end
  end
end
