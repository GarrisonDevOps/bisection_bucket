# frozen_string_literal: true

module Geo
  module Console
    class ShowUncachedSecondarySiteStatusAction < Action
      def name
        "Show uncached secondary site status (Slow. Will run all the queries)"
      end

      def execute
        current_node_status = GeoNodeStatus.current_node_status
        geo_node = current_node_status.geo_node

        Gitlab::Geo::GeoNodeStatusCheck.new(current_node_status, geo_node).print_status
      end
    end
  end
end
