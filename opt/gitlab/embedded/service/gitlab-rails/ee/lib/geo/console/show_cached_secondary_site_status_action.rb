# frozen_string_literal: true

module Geo
  module Console
    class ShowCachedSecondarySiteStatusAction < Action
      def name
        "Show cached secondary site status"
      end

      def execute
        current_node_status = GeoNodeStatus.fast_current_node_status
        unless current_node_status
          @output_stream.puts 'No status data in cache'
          return
        end

        geo_node = current_node_status.geo_node

        Gitlab::Geo::GeoNodeStatusCheck.new(current_node_status, geo_node).print_status
      end
    end
  end
end
