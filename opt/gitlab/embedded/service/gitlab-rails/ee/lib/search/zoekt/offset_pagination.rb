# frozen_string_literal: true

module Search
  module Zoekt
    module OffsetPagination
      MIN_VERSION = '1.9.0'

      def self.active?
        Node.all_at_least_version?(MIN_VERSION)
      end
    end
  end
end
