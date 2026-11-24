# frozen_string_literal: true

module Security
  module ScanProfiles
    class Configuration
      module Defaults
        module DependencyScanningPostProcessing
          VALUES = {
            auto_remediation: {
              cooldown: 7,
              severity_level: 'high',
              upgrade_policy: 'minor',
              open_merge_requests_limit: 30,
              runner_tags: [],
              batch_updates: false,
              max_updates_per_batch: 10
            }
          }.freeze
        end
      end
    end
  end
end
