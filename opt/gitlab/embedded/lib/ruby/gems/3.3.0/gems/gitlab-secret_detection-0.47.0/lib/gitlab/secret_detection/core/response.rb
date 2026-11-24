# frozen_string_literal: true

module Gitlab
  module SecretDetection
    module Core
      # Response is the data object returned by the scan operation with the following structure
      #
      # +status+:: One of values from Gitlab::SecretDetection::Core::Status indicating the scan operation's status
      # +results+:: Array of Gitlab::SecretDetection::Core::Finding values. Default value is nil.
      #   to embed more information on error.
      # +applied_exclusions+:: Array of exclusions that were applied during this scan.
      #   These can be either GRPC::Exclusions when used as a service, or `Security::ProjectSecurityExclusion
      #   object when used as a gem.
      # +metadata+:: Hash object containing additional meta information about the response. It is currently used
      class Response
        attr_reader :status, :results, :applied_exclusions, :metadata

        def initialize(status:, results: [], applied_exclusions: [], metadata: {})
          @status = status
          @results = results
          @applied_exclusions = applied_exclusions
          @metadata = metadata
        end

        def ==(other)
          self.class == other.class && other.state == state
        end

        def to_h
          {
            status:,
            results: results&.map(&:to_h),
            applied_exclusions:,
            metadata:
          }
        end

        protected

        def state
          [
            status,
            results,
            applied_exclusions,
            metadata
          ]
        end
      end
    end
  end
end
