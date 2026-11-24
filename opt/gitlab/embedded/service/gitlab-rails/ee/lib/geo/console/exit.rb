# frozen_string_literal: true

module Geo
  module Console
    class Exit < Choice
      def name
        "Exit Geo console"
      end

      def open
        # No op
      end
    end
  end
end
