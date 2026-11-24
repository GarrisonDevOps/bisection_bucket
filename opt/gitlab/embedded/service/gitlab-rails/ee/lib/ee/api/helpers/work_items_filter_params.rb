# frozen_string_literal: true

module EE
  module API
    module Helpers
      module WorkItemsFilterParams
        extend ActiveSupport::Concern

        def transform
          transformed = super

          rewrite_param_name(transformed, :iteration_wildcard_id, :iteration_id)
          rewrite_param_name(transformed[:not], :iteration_wildcard_id, :iteration_id)
          rewrite_param_name(transformed, :health_status_filter, :health_status)
          rewrite_param_name(transformed, :weight_wildcard_id, :weight)

          if transformed[:status]
            status_id = transformed[:status].delete(:id)

            if status_id && resource_parent
              namespace = resource_parent.root_ancestor
              transformed[:status][:id] = ::WorkItems::Statuses::Finder.new(namespace, { 'status_id' => status_id })
                .find_single_status
            end
          end

          transformed
        end
      end
    end
  end
end
