# frozen_string_literal: true

module Ai
  module Catalog
    module Flows
      module ReferenceLimits
        MAX_REFERENCES_PER_KIND = {
          agent: 20
        }.freeze

        # The resolved references go into one CI job variable, and Linux limits
        # one environment variable to 128 KiB. The limit leaves space for
        # serialization overhead and the variable name.
        # Revisited in https://gitlab.com/gitlab-org/gitlab/-/work_items/634359
        MAX_PAYLOAD_SIZE_PER_KIND = {
          agent: 112.kilobytes
        }.freeze

        def self.limit_for(kind)
          MAX_REFERENCES_PER_KIND.fetch(kind)
        end

        def self.count_exceeded?(kind, count)
          count > limit_for(kind)
        end

        def self.max_payload_size_for(kind)
          MAX_PAYLOAD_SIZE_PER_KIND.fetch(kind)
        end

        def self.payload_size_exceeded?(kind, bytesize)
          bytesize > max_payload_size_for(kind)
        end
      end
    end
  end
end
