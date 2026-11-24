# frozen_string_literal: true

module Gitlab
  module Duo
    module Administration
      class AgentPlatformWebsocketCheck
        include TlsSocketHelpers

        WEBSOCKET_PATH = 'api/v4/ai/duo_workflows/ws'
        CONNECT_TIMEOUT = 15
        READ_TIMEOUT = 15
        HEADER_TERMINATORS = ["\r\n", "\n"].freeze

        Result = Struct.new(
          :status, :http_status, :headers, :error, :url, :response_time_ms, :tls_verified, keyword_init: true
        ) do
          def ok?
            status == :ok
          end
        end

        def initialize(user)
          @user = user
        end

        def execute
          started_at = Time.current
          url = Gitlab::Utils.append_path(Gitlab.config.gitlab.url, WEBSOCKET_PATH)
          uri = URI.parse(url)

          http_status, headers = handshake(uri, access_token)

          Result.new(
            status: classify(http_status),
            http_status: http_status,
            headers: headers,
            url: url,
            response_time_ms: elapsed_ms(started_at),
            tls_verified: @tls_verified
          )
        rescue StandardError => e
          Result.new(status: :error, error: e, url: url, response_time_ms: elapsed_ms(started_at))
        end

        private

        attr_reader :user

        def classify(http_status)
          case http_status
          when 101 then :ok
          when 401, 403 then :rejected
          else :not_upgraded
          end
        end

        def handshake(uri, token)
          socket = open_socket(uri)
          socket.post_connection_check(uri.host) if @tls_verified
          socket.write(request(uri, token))

          raise Timeout::Error, 'timed out waiting for a handshake response' unless socket.wait_readable(READ_TIMEOUT)

          status_line = socket.gets.to_s
          headers = {}
          loop do
            line = socket.gets
            break if line.nil? || HEADER_TERMINATORS.include?(line)

            key, _, value = line.chomp.partition(': ')
            headers[key] = value
          end

          [status_line[%r{\AHTTP/\d(?:\.\d)? (\d{3})}, 1].to_i, headers]
        ensure
          socket&.close
        end

        def open_socket(uri)
          return tcp_socket(uri.host, uri.port) unless uri.is_a?(URI::HTTPS)

          socket, @tls_verified = open_tls_socket(uri.host, uri.port)
          socket
        end

        def request(uri, token)
          [
            "GET #{uri.request_uri} HTTP/1.1",
            "Host: #{uri.authority}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Key: #{Base64.strict_encode64(SecureRandom.random_bytes(16))}",
            "Sec-WebSocket-Version: 13",
            "Origin: #{uri.origin}",
            "Authorization: Bearer #{token}",
            "\r\n"
          ].join("\r\n")
        end

        def access_token
          result = ::Ai::DuoWorkflows::WorkflowContextGenerationService
            .new(
              current_user: user,
              organization: user.organization, # rubocop:disable Gitlab/AvoidUserOrganization -- runs outside a request where Current.organization is not set
              surface: ::Ai::ToolRules::GovernanceSurface::WEB
            )
            .generate_oauth_token

          raise result.message if result.respond_to?(:error?) && result.error?

          result[:oauth_access_token].plaintext_token
        end

        def elapsed_ms(started_at)
          ((Time.current - started_at) * 1000).round(2)
        end
      end
    end
  end
end
