# frozen_string_literal: true

module Geo
  module Console
    class ShowAllSiteStatusDataAction < Action
      def name
        "Show all Geo site status data in the main PostgreSQL DB"
      end

      def execute
        PP.pp GeoNodeStatus.all, @output_stream
        @output_stream.puts ""
      end
    end
  end
end
