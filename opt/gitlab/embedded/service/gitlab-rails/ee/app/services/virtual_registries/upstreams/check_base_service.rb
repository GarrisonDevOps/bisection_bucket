# frozen_string_literal: true

module VirtualRegistries
  module Upstreams
    class CheckBaseService
      ERRORS = ::VirtualRegistries::BaseService::BASE_ERRORS.merge(
        file_not_found_on_upstreams: ServiceResponse.error(
          message: 'File not found on any upstream',
          reason: :file_not_found_on_upstreams
        )
      ).freeze

      NETWORK_TIMEOUT = ::VirtualRegistries::BaseService::NETWORK_TIMEOUT

      def initialize(upstreams:, params: {})
        @upstreams = upstreams
        @params = params
        @results = Array.new(upstreams.size)
      end

      def execute
        return ERRORS[:path_not_present] unless path.present?
        return ERRORS[:file_not_found_on_upstreams] unless upstreams.any?

        check
      end

      private

      attr_reader :upstreams, :params, :results

      # Returns the index of the first true value that is preceded only by false values.
      # Returns nil otherwise.
      #
      # Examples:
      #   [false, false, true, true]  => 2   (first true at index 2, all preceding are false)
      #   [false, nil, true, false]   => nil (nil before true, not all preceding are false)
      #   [true, false, nil]          => 0   (first true at index 0, no preceding values)
      #   [false, false, false]       => nil (no true values)
      def first_successful_index
        results.find_index.with_index { |e, i| e && results[0...i].all?(false) }
      end

      def path
        params[:path]
      end
    end
  end
end
