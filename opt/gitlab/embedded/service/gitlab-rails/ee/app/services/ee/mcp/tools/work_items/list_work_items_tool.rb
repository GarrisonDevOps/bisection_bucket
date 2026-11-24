# frozen_string_literal: true

module EE
  module Mcp
    module Tools
      module WorkItems
        module ListWorkItemsTool
          extend ::Gitlab::Utils::Override

          protected

          override :agent_filters
          def agent_filters
            super.merge(
              'healthStatusFilter' => params[:health_status_filter],
              'status' => params[:status]
            ).compact
          end
        end
      end
    end
  end
end
