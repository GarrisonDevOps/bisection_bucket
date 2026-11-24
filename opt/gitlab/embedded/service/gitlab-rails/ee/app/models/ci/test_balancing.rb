# frozen_string_literal: true

module Ci
  module TestBalancing
    MAX_TEST_SPLITS_PER_JOB_GROUP = 50_000
    LAST_SEEN_THROTTLE_INTERVAL = 24.hours

    def self.table_name_prefix
      "ci_test_balancing_"
    end
  end
end
