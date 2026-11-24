# frozen_string_literal: true

module Gitlab
  module Geo
    class BaseRequest
      GITLAB_GEO_AUTH_TOKEN_TYPE = 'GL-Geo'

      attr_reader :request_data

      def initialize(request_data = {})
        @request_data = request_data
      end

      # Raises GeoNodeNotFoundError if current node is not a Geo node
      def headers
        {
          'Authorization' => authorization,
          'X-Request-ID' => correlation_id
        }
      end

      def authorization
        geo_auth_token(request_data)
      end

      def expiration_time
        1.minute
      end

      private

      def correlation_id
        Labkit::Correlation::CorrelationId.current_or_new_id
      end

      def geo_auth_token(message)
        signed_data = Gitlab::Geo::SignedData
          .new(
            geo_node: requesting_node,
            validity_period: expiration_time
          )
          .sign_and_encode_data(message)

        "#{GITLAB_GEO_AUTH_TOKEN_TYPE} #{signed_data}"
      end

      def requesting_node
        Gitlab::Geo.current_node
      end
    end
  end
end
