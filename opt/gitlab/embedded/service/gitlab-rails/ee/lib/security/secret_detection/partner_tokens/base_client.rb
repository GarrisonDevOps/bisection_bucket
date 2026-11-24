# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      class BaseClient
        include Gitlab::Utils::StrongMemoize

        NetworkError = Class.new(StandardError)
        ResponseError = Class.new(StandardError)
        RateLimitError = Class.new(ResponseError)

        TokenStatus = Struct.new(:status, :metadata, keyword_init: true) do
          ::Security::TokenStatus::STATUSES.each_key do |state|
            define_method(:"#{state}?") do
              status == state
            end
          end
        end

        def verify_token(token_value)
          token_value = strip_quotes(token_value)

          # A blank value cannot be a live credential. Sending it would earn a 401,
          # which maps to inactive - a revoked verdict for a secret never checked.
          return token_response(:unknown) if token_value.blank?

          return token_response(:unknown) unless valid_format?(token_value)

          result = nil
          duration = Benchmark.realtime do
            result = verify_partner_token(token_value)
          end

          record_api_success(duration)
          result

        rescue RateLimitError => e
          record_rate_limit_error
          raise e
        rescue NetworkError => e
          record_network_error(e)
          raise e
        rescue ResponseError => e
          ::Gitlab::ErrorTracking.log_exception(e)
          record_api_failure('response_error')
          token_response(:unknown)
        end

        # The registry routes on the rule id, so a client does not re-check the
        # ruleset regex. Override only when one rule id admits several credential
        # shapes and the client can verify just some of them.
        def valid_format?(_token_value)
          true
        end

        def verify_partner_token(token_value)
          raise NotImplementedError, 'Subclasses must implement verify_partner_token'
        end

        protected

        def make_request(url, method: :get, headers: {}, body: nil)
          case method.to_sym
          when :get
            Integrations::Clients::HTTP.get(url, headers: headers)
          when :post
            Integrations::Clients::HTTP.post(url, body: body, headers: headers)
          end
        rescue *Gitlab::HTTP::HTTP_TIMEOUT_ERRORS => e
          raise NetworkError, "Request timeout: #{e.message}"
        rescue Errno::ECONNREFUSED, Errno::ECONNRESET, SocketError => e
          raise NetworkError, "Connection error: #{e.message}"
        rescue Net::HTTPError => e
          raise NetworkError, "HTTP error: #{e.message}"
        rescue StandardError => e
          raise NetworkError, "Unexpected error: #{e.message}"
        end

        def parse_json_response(response)
          return {} if response.body.blank?

          ::Gitlab::Json.safe_parse(response.body)
        rescue JSON::ParserError => e
          raise ResponseError, "Invalid JSON response: #{e.message}"
        end

        def parse_xml_response(response)
          return Nokogiri::XML('<empty/>') if response.body.blank?

          Nokogiri::XML(response.body, &:strict)
        rescue Nokogiri::XML::SyntaxError => e
          raise ResponseError, "Invalid XML response: #{e.message}"
        end

        def token_response(status)
          TokenStatus.new(
            status: status,
            metadata: build_metadata
          )
        end

        private

        # Rules without a capture group match the token with its surrounding quotes.
        def strip_quotes(token_value)
          token_value&.sub(/\A['"](.*)['"]\z/, '\\1')
        end

        def build_metadata
          {
            partner: partner_name.upcase,
            verified_at: Time.current.iso8601
          }
        end

        def partner_name
          @partner_name ||= self.class.name.demodulize.sub('Client', '').downcase
        end
        strong_memoize_attr :partner_name

        def record_api_success(duration)
          ::Gitlab::Metrics::SecretDetection::PartnerTokens.observe_api_duration(
            duration,
            partner: partner_name
          )

          ::Gitlab::Metrics::SecretDetection::PartnerTokens.increment_api_requests(
            partner: partner_name,
            status: 'success'
          )
        end

        def record_api_failure(error_type)
          ::Gitlab::Metrics::SecretDetection::PartnerTokens.increment_api_requests(
            partner: partner_name,
            status: 'failure',
            error_type: error_type
          )
        end

        def record_network_error(exception)
          error_class = exception.class.name.demodulize

          ::Gitlab::Metrics::SecretDetection::PartnerTokens.increment_network_errors(
            partner: partner_name,
            error_class: error_class
          )

          record_api_failure('network_error')
        end

        def record_rate_limit_error
          record_api_failure('rate_limit')
        end
      end
    end
  end
end
