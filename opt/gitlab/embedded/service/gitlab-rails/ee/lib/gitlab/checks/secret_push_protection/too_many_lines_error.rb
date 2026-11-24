# frozen_string_literal: true

module Gitlab
  module Checks
    module SecretPushProtection
      class TooManyLinesError < StandardError
        attr_reader :lines_count, :lines_threshold

        def initialize(lines_count, lines_threshold)
          @lines_count = lines_count
          @lines_threshold = lines_threshold
          super("Lines count (#{lines_count}) exceeds threshold of #{lines_threshold}")
        end
      end
    end
  end
end
