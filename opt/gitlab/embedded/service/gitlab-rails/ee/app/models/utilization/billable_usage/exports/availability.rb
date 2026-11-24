# frozen_string_literal: true

module Utilization
  module BillableUsage
    module Exports
      # Whether this instance can produce a billable usage report at all. The page, its
      # entry point and the download endpoint all gate on this, so they cannot disagree
      # about whether the feature exists.
      module Availability
        def self.enabled?
          ::Feature.enabled?(:billable_usage_export, :instance) &&
            ::Gitlab::BillingEvents::Client.new.local_persistence_enabled?
        end
      end
    end
  end
end
