# frozen_string_literal: true

module ArtifactRegistry
  class ErrorMapping
    include Errors
    include Guards

    DIGEST_SHAPE_REGEX = /\A[a-z0-9]+(?:[+._-][a-z0-9]+)*:\h{32,128}\z/
    # A JSON error body without AR's envelope came from an intermediary; its other fields may carry credentials.
    ERROR_SNIPPET_KEYS = %w[detail message title].freeze

    def initialize(reporting)
      @reporting = reporting
    end

    def raise_error(status, response, http_method, **attribution)
      envelope = error_envelope(response)
      message = envelope[:message]
      request_id = envelope[:request_id] || header_request_id(response)

      case status
      when 401, 403
        raise_terminal(AuthorizationError, message, http_method,
          status: status, request_id: request_id, code: envelope[:code], **attribution)
      when 429, 500..599
        raise_terminal(UnavailableError, message, http_method,
          status: status, request_id: request_id, code: envelope[:code], **attribution)
      else
        raise ApiError.new(
          message, status: status, code: envelope[:code], request_id: request_id, details: envelope[:details]
        )
      end
    end

    def raise_transport_error(error, http_method, **attribution)
      case error
      when ::Faraday::ParsingError
        status = error.response_status
        raise ApiError.new(status: 404) if status == 404

        error_class = [401, 403].include?(status) ? AuthorizationError : UnavailableError
        raise_terminal(error_class, 'Artifact Registry returned an unreadable response', http_method,
          status: status, cause: error, **attribution)
      when ::Faraday::SSLError
        raise_terminal(UnavailableError, "Artifact Registry TLS connection failed: #{error.message}",
          http_method, cause: error, **attribution)
      else
        raise_terminal(UnavailableError, 'Artifact Registry request failed', http_method, cause: error, **attribution)
      end
    end

    private

    delegate :raise_terminal, :log_error, :redacted_snippet, to: :@reporting, private: true

    def error_envelope(response)
      body = response.body
      error = body['error'] if body.is_a?(Hash)

      return { code: nil, message: redacted_snippet(error), request_id: nil } if error.is_a?(String)
      return error_snippet_envelope(body) unless error.is_a?(Hash)

      {
        code: redacted_snippet(error['code'].to_s),
        message: redacted_snippet(error['message'].to_s),
        request_id: redacted_snippet(error['request_id'].to_s),
        details: allowlisted_details(error['details'])
      }
    end

    def error_snippet_envelope(body)
      snippet =
        case body
        when String then redacted_snippet(body)
        when Hash then redacted_snippet(body.values_at(*ERROR_SNIPPET_KEYS).grep(String).join(' '))
        end

      { code: nil, message: snippet, request_id: nil }
    end

    def header_request_id(response)
      redacted_snippet(response.headers['X-Request-Id'])
    end

    # details skip redacted_snippet and reach GraphQL callers, so every key needs a strict shape check.
    def allowlisted_details(details)
      return unless details.is_a?(Hash)

      {
        'repository_ids' => allowlisted_repository_ids(details['repository_ids']),
        'parents' => allowlisted_parent_digests(details['parents']),
        'upstream_repository_id' => allowlisted_upstream_repository_id(details['upstream_repository_id'])
      }.compact.presence
    end

    def allowlisted_upstream_repository_id(id)
      id if canonical_uuid?(id)
    end

    def allowlisted_repository_ids(ids)
      return unless carried_list?(ids) && ids.all? { |id| ::Gitlab::UUID.v7?(id) }

      ids
    end

    def allowlisted_parent_digests(digests)
      return unless carried_list?(digests)
      return digests if digests.all? { |digest| digest.match?(DIGEST_SHAPE_REGEX) }

      log_error(Error.new("Artifact Registry sent #{digests.size} parent digests, not all of the digest shape"))

      nil
    end

    def carried_list?(values)
      values.is_a?(Array) && values.present? && values.all?(String)
    end
  end
end
