# frozen_string_literal: true

module Geo
  # Skips the entire worker in the context of a Geo secondary site
  #
  # If you need more granular control, use SkipReplica
  module SkipSecondary
    def perform(*args)
      if ::Gitlab::Geo.secondary?
        geo_logger.info(structured_payload(
          message: 'geo_secondary_skip setting is enabled. Job was skipped',
          args: args
        ))
        return
      end

      super
    end

    private

    def geo_logger
      Gitlab::Geo::Logger
    end
  end
end
