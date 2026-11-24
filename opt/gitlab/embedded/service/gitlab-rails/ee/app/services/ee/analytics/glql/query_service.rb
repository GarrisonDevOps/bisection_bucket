# frozen_string_literal: true

module EE
  module Analytics
    module Glql
      module QueryService
        extend ::Gitlab::Utils::Override

        private

        # The Elasticsearch transport interceptor raises Elastic::TimeoutError for client timeouts and 408/504
        # responses. On the default typhoeus adapter that includes connect timeouts, which curl reports the
        # same way. Other connection failures arrive as Gitlab::Search::Client::ConnectionError.
        #
        # @return [Array<Module>]
        override :timeout_errors
        def timeout_errors
          super + [::Elastic::TimeoutError]
        end
      end
    end
  end
end
