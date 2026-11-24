# frozen_string_literal: true

module Gitlab
  module Checks
    module SecretPushProtection
      class TooManyChangedPathsError < StandardError
        attr_reader :changed_paths_count, :changed_paths_threshold

        def initialize(changed_paths_count, changed_paths_threshold)
          @changed_paths_count = changed_paths_count
          @changed_paths_threshold = changed_paths_threshold
          super("Changed paths count (#{changed_paths_count}) exceeds threshold of #{changed_paths_threshold}")
        end
      end
    end
  end
end
