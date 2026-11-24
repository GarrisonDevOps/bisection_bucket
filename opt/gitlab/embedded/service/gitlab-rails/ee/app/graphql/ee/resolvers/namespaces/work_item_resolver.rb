# ee/app/graphql/ee/resolvers/namespaces/work_item_resolver.rb
# frozen_string_literal: true

module EE
  module Resolvers
    module Namespaces
      module WorkItemResolver
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        class_methods do
          extend ::Gitlab::Utils::Override

          override :recent_services_map
          def recent_services_map
            super.merge(
              'epic' => ::Gitlab::Search::RecentEpics
            )
          end
        end

        private

        override :log_recent_view
        def log_recent_view(work_item)
          base_type = work_item.work_item_type.base_type

          # Only handle Epic WorkItems in EE, delegate everything else to parent
          if base_type == 'epic' && work_item.synced_epic
            service_class = self.class.recent_services_map[base_type]
            return unless service_class

            epic = work_item.synced_epic
            service_class.new(user: current_user).log_view(epic)
            ::Gitlab::Search::RecentWorkItems.new(user: current_user).log_view(work_item)
          else
            # Delegate to parent implementation for all non-Epic WorkItems
            super
          end
        end
      end
    end
  end
end
