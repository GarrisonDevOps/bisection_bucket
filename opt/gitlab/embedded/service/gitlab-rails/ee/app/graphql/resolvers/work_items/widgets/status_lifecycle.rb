# frozen_string_literal: true

module Resolvers
  module WorkItems
    module Widgets
      module StatusLifecycle
        extend ActiveSupport::Concern
        include ::Gitlab::Utils::StrongMemoize

        private

        def status_lifecycle
          return unless root_ancestor&.licensed_feature_available?(:work_item_status)

          work_item_type.status_lifecycle_for(root_ancestor&.id)
        end

        def root_ancestor
          context[:resource_parent]&.root_ancestor
        end
        strong_memoize_attr :root_ancestor

        def work_item_type
          object.work_item_type
        end
        strong_memoize_attr :work_item_type
      end
    end
  end
end
