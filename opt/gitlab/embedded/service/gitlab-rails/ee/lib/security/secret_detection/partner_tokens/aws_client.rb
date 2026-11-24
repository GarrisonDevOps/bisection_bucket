# frozen_string_literal: true

module Security
  module SecretDetection
    module PartnerTokens
      class AwsClient < BaseClient
        STS_ENDPOINT = 'https://sts.amazonaws.com/'
        DUMMY_SECRET = 'DUMMY_SECRET_FOR_AWS_AUTH_PROBING_NOT_REAL'

        private

        # The AWS rule id matches AKIA, ASIA and A3T keys, but the dummy-secret
        # STS test below only reads correctly for long-term AKIA keys. An ASIA key
        # needs its session token, and STS answers InvalidClientTokenId without
        # it, which would report a live credential as dead.
        # Ref: https://gitlab.com/gitlab-org/security-products/secret-detection/secret-detection-rules/-/blob/main/rules/mit/aws/aws.toml
        def valid_format?(access_key_id)
          return false unless access_key_id

          access_key_id.match?(/\AAKIA[0-9A-Z]{16}\z/)
        end

        # Use dummy secret to probe AWS error responses for access key status
        #
        # APPROACH RATIONALE:
        # AWS STS API requires both Access Key ID and Secret Access Key, but GitLab's secret detection
        # only identifies the Access Key ID. Since we don't have the corresponding secret, we use a
        # "dummy secret" approach to probe AWS error responses:
        #
        # 1. Valid token + dummy secret: 403 with Error.Code = "SignatureDoesNotMatch" : ACTIVE TOKEN
        # 2. Invalid token + dummy secret: 403 with Error.Code = "InvalidClientTokenId" : INACTIVE TOKEN
        #
        # RISKS & MITIGATION:
        # - Risk: AWS could change API or error codes, breaking verification logic
        # - Mitigation: Vendors typically version APIs instead of breaking changes
        # - Future: Could implement sanity checks or engage AWS for dedicated verification endpoint
        #
        # This approach balances practical implementation constraints with effective token verification.
        def verify_partner_token(access_key_id)
          response = make_sts_request(access_key_id)
          analyze_aws_error_response(response, access_key_id)
        end

        def make_sts_request(access_key_id)
          url = STS_ENDPOINT

          timestamp = Time.now.utc.strftime('%Y%m%dT%H%M%SZ')
          date = timestamp[0..7]

          body = URI.encode_www_form({
            'Action' => 'GetCallerIdentity',
            'Version' => '2011-06-15'
          })

          headers = build_aws_auth_headers(access_key_id, timestamp, date)

          make_request(url, method: :post, headers: headers, body: body)
        end

        def build_aws_auth_headers(access_key_id, timestamp, date)
          # Create minimal AWS auth header with dummy credentials
          # This will fail authentication, but that's expected - we want the error type
          credential = "#{access_key_id}/#{date}/us-east-1/sts/aws4_request"

          # Create a basic (intentionally wrong) signature
          string_to_sign = "AWS4-HMAC-SHA256\n#{timestamp}\n#{date}/us-east-1/sts/aws4_request\ndummyhash"
          signature = OpenSSL::HMAC.hexdigest('sha256', "AWS4#{DUMMY_SECRET}", string_to_sign)

          auth_header = "AWS4-HMAC-SHA256 Credential=#{credential}, " \
            "SignedHeaders=host;x-amz-date, Signature=#{signature}"

          {
            'Authorization' => auth_header,
            'X-Amz-Date' => timestamp,
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Host' => 'sts.amazonaws.com'
          }
        end

        def analyze_aws_error_response(response, access_key_id)
          case response.code.to_i
          when 200
            # Shouldn't happen with dummy credentials, but handle gracefully
            token_response(:active)

          when 403
            # Parse AWS error response to determine access key status
            error_details = parse_aws_error_response(response)
            classify_aws_error(error_details, access_key_id)

          when 429, 503
            # AWS rate limiting
            raise RateLimitError, "AWS STS rate limited: #{response.code}"

          when 500, 502, 504
            # AWS service errors - should retry
            raise NetworkError, "AWS service error: #{response.code}"

          else
            # Other unexpected responses
            token_response(:unknown)
          end
        end

        def parse_aws_error_response(response)
          xml_doc = parse_xml_response(response)

          error_code = extract_text_from_xml(xml_doc, 'Code') || 'UnknownError'
          error_message = extract_text_from_xml(xml_doc, 'Message') || 'No error message'

          {
            code: error_code,
            message: error_message
          }
        end

        def classify_aws_error(error_details, _access_key_id)
          case error_details[:code]
          when 'SignatureDoesNotMatch', 'InvalidSignature'
            # Access key exists and is active (wrong signature is expected with dummy credentials)
            token_response(:active)
          else
            # Access key is inactive (doesn't exist, deactivated, revoked, etc.)
            token_response(:inactive)
          end
        end

        def extract_text_from_xml(xml_doc, element_name)
          xml_doc.xpath("//*[local-name()='#{element_name}']").text.presence
        end
      end
    end
  end
end
