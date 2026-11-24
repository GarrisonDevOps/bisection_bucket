# frozen_string_literal: true

module Analytics
  module KnowledgeGraph
    class QueryRunner
      Response = Data.define(:status, :content_type, :body, :error_reason) do
        def initialize(status:, content_type:, body:, error_reason: nil)
          super
        end

        def self.json(body, status: 200, error_reason: nil)
          new(status: status, content_type: JSON_TYPE, body: "#{body}\n", error_reason: error_reason)
        end

        def self.text(body, status: 200)
          new(status: status, content_type: TEXT_TYPE, body: body)
        end
      end

      Frame = Data.define(:content_type, :head, :tail, :json_escaped) do
        def self.split(response, json_escaped: false)
          head, tail = response.body.split(STREAM_SENTINEL, 2)
          new(content_type: response.content_type, head: head, tail: tail, json_escaped: json_escaped)
        end

        def encode(text)
          json_escaped ? ::Gitlab::Json.generate(text)[1...-1] : text
        end
      end

      StreamBody = Data.define(:context, :producer, :closer) do
        def each(&block)
          ::Labkit::Context.with_context(context) { producer.call(&block) }
        end

        def close
          closer.call
        end
      end

      class RestRenderer
        def ok(body, type:)
          type == :json ? Response.json(body) : Response.text(body)
        end

        def stream_frame(type:)
          Frame.split(ok(STREAM_SENTINEL, type: type))
        end

        def query_error(code, message, reason)
          payload = { code: code, message: message }
          payload[:reason] = reason if reason.present?
          Response.json(::Gitlab::Json.generate(payload), status: ERROR_HTTP_STATUS.fetch(code, 400))
        end

        def failure(_message, status)
          Response.text("#{Rack::Utils::HTTP_STATUS_CODES[status]}\n", status: status)
        end
      end

      # Returns the graph as data instead of an HTTP response, for in-process callers.
      class DataRenderer
        Result = Data.define(:body, :error_code)

        PASSTHROUGH_CODES = %w[quota_exhausted timeout].freeze
        EXECUTION_ERROR = 'execution_error'

        def ok(body, type:)
          parsed = type == :json ? ::Gitlab::Json::SafeParser.parse(body)['result'] : body
          Result.new(body: parsed, error_code: nil)
        end

        def query_error(code, _message, _reason)
          Result.new(body: nil, error_code: PASSTHROUGH_CODES.include?(code) ? code : EXECUTION_ERROR)
        end

        def failure(_message, status)
          Result.new(body: nil, error_code: status == 504 ? 'timeout' : EXECUTION_ERROR)
        end
      end

      McpRenderer = Struct.new(:id) do
        def self.tool_result(text, is_error:)
          { content: [{ type: 'text', text: text }], isError: is_error }
        end

        def ok(body, **)
          envelope(body)
        end

        def stream_frame(**)
          Frame.split(ok(STREAM_SENTINEL), json_escaped: true)
        end

        def query_error(code, message, _reason)
          envelope(message, error_status: ERROR_HTTP_STATUS.fetch(code, 400))
        end

        def failure(message, status)
          envelope(message, error_status: status)
        end

        private

        def envelope(text, error_status: nil)
          result = self.class.tool_result(text, is_error: !error_status.nil?)
          reason = ::Mcp::Tools::Base::Response.reason_for_http_status(error_status) if error_status
          body = { jsonrpc: ::API::Helpers::Mcp::JsonRpc::Constants::JSONRPC_VERSION, result: result, id: id }
          Response.json(::Gitlab::Json.generate(body), error_reason: reason)
        end
      end

      class StreamFailure < StandardError
        attr_reader :http_status

        def initialize(message, http_status)
          super(message)
          @http_status = http_status
        end
      end

      RetryableError = Class.new(StandardError)
      ClientClosed = Class.new(StandardError)
      StreamAborted = Class.new(IOError)

      METHOD = '/orbit.v1.OrbitService/ExecuteQuery'
      MAX_STREAM_MESSAGES = 10
      MAX_TIMEOUT_SECONDS = 120
      DEFAULT_TIMEOUT_SECONDS = 30
      RACK_TIMEOUT_MARGIN_SECONDS = 2
      MAX_ATTEMPTS = 2
      REDACTION_SOURCE = 'orbit_rails'
      STREAM_SENTINEL = 'orbit-stream-sentinel'
      JSON_TYPE = 'application/json'
      TEXT_TYPE = 'text/plain; charset=utf-8'
      CLIENT_CLOSED_STATUS = 499
      TIMEOUT_MESSAGE = 'orbit query: query did not finish in time, narrow the query and try again'
      STREAM_ERROR_MESSAGE = 'orbit query: stream error'
      CODE_QUOTA_EXHAUSTED = 'quota_exhausted'
      REASON_CREDITS_EXHAUSTED = 'GITLAB_CREDITS_EXHAUSTED'
      ERROR_HTTP_STATUS = {
        'compile_error' => 400,
        'validation_error' => 400,
        'execution_error' => 502,
        'internal_error' => 502,
        'timeout' => 504,
        CODE_QUOTA_EXHAUSTED => 402
      }.freeze
      PROTO_FORMATS = { 'llm' => :RESPONSE_FORMAT_LLM, 'gql' => :RESPONSE_FORMAT_GQL }.freeze
      STREAM_CONTENT = %i[result_chunk result].freeze
      BUFFERED_CONTENT = %i[result_chunk result error].freeze
      OPS = ::GRPC::Core::CallOps
      CODES = ::GRPC::Core::StatusCodes

      def self.params_for(
        query:, user:, format:, query_type: :raw, mcp_id: nil, request_context: RequestContext.new,
        language: GrpcClient::DEFAULT_QUERY_LANGUAGE
      )
        GoverningNamespaceGuard.ensure_selected!(user)

        endpoint = GrpcClient.configured_endpoint
        secure = GrpcClient.secure_channel?(endpoint)

        headers = GrpcClient.outgoing_headers
        headers['x-client-user-agent'] = request_context.user_agent if request_context.user_agent.present?

        if secure || GrpcClient.private_address?(endpoint)
          jwt = JwtAuth.generate_token(user: user, request_context: request_context)
          headers = headers.merge('authorization' => "Bearer #{jwt}") if jwt
        end

        params = {
          'GkgServer' => { 'address' => endpoint, 'headers' => headers },
          'Query' => query,
          'Language' => language.to_s,
          'Format' => format.to_s,
          'TimeoutSeconds' => configured_timeout_seconds
        }
        params['QueryType'] = query_type.to_s unless query_type.to_s == 'raw'
        params['McpId'] = mcp_id unless mcp_id.nil?
        params
      end

      def self.configured_timeout_seconds
        ::Gitlab.config.knowledge_graph.streaming_timeout_seconds
      rescue ::Gitlab::Configs::MissingConfig
        ENV.fetch('KNOWLEDGE_GRAPH_STREAMING_TIMEOUT', DEFAULT_TIMEOUT_SECONDS).to_i
      end
      private_class_method :configured_timeout_seconds

      def initialize(params, user:, env: {}, renderer: nil)
        @params = params
        @user = user
        @env = env
        @renderer = renderer || (params['McpId'].nil? ? RestRenderer.new : McpRenderer.new(params['McpId']))
        @format = params['Format'].to_s
      end

      def execute
        @start = ::Gitlab::Metrics::System.monotonic_time
        raise StreamFailure.new(TIMEOUT_MESSAGE, 504) if timeout_seconds <= 0

        @log_context = ::Labkit::Context.current.to_h
        release_request_resources!
        response = run_with_retry
        observe_grpc(@failed ? 'error' : 'ok') unless @streaming
        response
      rescue ClientClosed
        observe_grpc('cancelled')
        Response.text('', status: CLIENT_CLOSED_STATUS)
      rescue StreamFailure => e
        observe_grpc('error')
        fail_query(e.message, e.http_status)
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e, user_id: user.id)
        observe_grpc('error')
        fail_query('orbit query: internal error', 502)
      end

      private

      attr_reader :params, :user, :env, :renderer, :format

      def run_with_retry
        attempt = 0
        begin
          attempt += 1
          run_stream
        rescue RetryableError
          retry if attempt < MAX_ATTEMPTS && !deadline_passed?

          raise StreamFailure.new(STREAM_ERROR_MESSAGE, 502)
        end
      end

      def run_stream
        call = GrpcClient.channel(params.dig('GkgServer', 'address'))
          .create_call(nil, ::GRPC::Core::PropagateMasks::DEFAULTS, METHOD, nil, deadline)
        received = false
        watch = DisconnectWatcher.watch(env['puma.socket'], call)

        begin
          call.run_batch(OPS::SEND_INITIAL_METADATA => metadata, OPS::SEND_MESSAGE => initial_message.to_proto)
        rescue ::GRPC::Core::CallError
          return stream_ended(call, watch, received)
        end

        MAX_STREAM_MESSAGES.times do
          batch = call.run_batch(received ? recv_ops : recv_ops.merge(OPS::RECV_INITIAL_METADATA => nil))
          return stream_ended(call, watch, received) if batch.message.nil?

          received = true
          response = dispatch(call, watch, ::Orbit::V1::ExecuteQueryMessage.decode(batch.message))
          return response if response
        end

        raise StreamFailure.new("orbit query: exceeded #{MAX_STREAM_MESSAGES} stream messages without result", 502)
      rescue ::GRPC::Core::CallError => e
        call_failed(watch, e)
      ensure
        close_call(call, watch) unless @streaming
      end

      def close_call(call, watch)
        call&.cancel
        call&.close
        DisconnectWatcher.unwatch(watch)
      end

      def dispatch(call, watch, msg)
        case msg.content
        when :redaction
          raise ClientClosed if watch&.cancelled

          reply = redaction_reply(msg.redaction.required)
          call.run_batch(OPS::SEND_MESSAGE => reply.to_proto) if reply
          nil
        when :result_chunk
          return stream_response(call, watch, msg.result_chunk.data) if renderer.respond_to?(:stream_frame)

          buffered_chunks_response(call, watch, msg.result_chunk.data)
        when :result
          finish(call)
          result_response(msg.result)
        when :error
          finish(call)
          query_error(msg.error.code, msg.error.message)
        end
      end

      def call_failed(watch, error)
        raise ClientClosed if watch&.cancelled

        metrics.increment_grpc_error('execute_query', 'call_error')
        raise StreamFailure.new(TIMEOUT_MESSAGE, 504) if deadline_passed?

        log_error('call_error', error.message)
        raise StreamFailure.new(STREAM_ERROR_MESSAGE, 502)
      end

      def recv_ops
        { OPS::RECV_MESSAGE => nil }
      end

      def finish(call)
        call.run_batch(OPS::SEND_CLOSE_FROM_CLIENT => nil, OPS::RECV_STATUS_ON_CLIENT => nil)
      rescue ::GRPC::Core::CallError
        nil
      end

      def stream_ended(call, watch, received)
        status = call.run_batch(OPS::RECV_STATUS_ON_CLIENT => nil).status
        raise ClientClosed if watch&.cancelled

        metrics.increment_grpc_error('execute_query', status.code.to_s)

        if status.code == CODES::RESOURCE_EXHAUSTED && deny_reason(status) == REASON_CREDITS_EXHAUSTED
          return query_error(CODE_QUOTA_EXHAUSTED, status.details, REASON_CREDITS_EXHAUSTED)
        end

        raise StreamFailure.new(TIMEOUT_MESSAGE, 504) if status.code == CODES::DEADLINE_EXCEEDED || deadline_passed?
        raise RetryableError if status.code == CODES::UNAVAILABLE && !received
        raise StreamFailure.new('orbit query: stream ended without result', 502) if status.code == CODES::OK

        error = GrpcClient::ConnectionError.new(
          'execute_query failed', grpc_code: status.code, grpc_details: status.details
        )
        return query_error('invalid_request', status.details) if error.client_error? && status.details.present?

        log_error('stream_status', "#{status.code}: #{status.details}")
        raise StreamFailure.new(STREAM_ERROR_MESSAGE, 502)
      end

      def deny_reason(status)
        rpc_status = ::GRPC::BadStatus.new_status_exception(status.code, status.details, status.metadata).to_rpc_status
        return unless rpc_status

        require 'google/rpc/error_details_pb'
        rpc_status.details.each do |any|
          info = any.unpack(::Google::Rpc::ErrorInfo)
          return info.reason if info
        end
        nil
      end

      def redaction_reply(required)
        return unless required

        results = redact(required.resources)
        ::Orbit::V1::ExecuteQueryMessage.new(
          redaction: ::Orbit::V1::RedactionExchange.new(
            response: ::Orbit::V1::RedactionResponse.new(
              result_id: required.result_id,
              authorizations: results.map do |type, id_map|
                ::Orbit::V1::ResourceAuthorization.new(resource_type: type, authorized: id_map)
              end
            )
          )
        )
      end

      def redact(resources)
        resources_by_type = {}
        resources.each do |r|
          r.abilities.each do |ability|
            if resources_by_type.key?(r.resource_type)
              raise StreamFailure.new("orbit query: duplicate resource_type '#{r.resource_type}'", 502)
            end

            resources_by_type[r.resource_type] = { 'ids' => r.resource_ids.to_a, 'ability' => ability }
          end
        end

        ::Authz::RedactionService.new(
          user: user, resources_by_type: resources_by_type, source: REDACTION_SOURCE,
          metrics_observer: method(:observe_redaction)
        ).execute
      ensure
        release_request_resources!
      end

      def result_response(result, chunked_data = nil)
        return renderer.ok(chunked_data || result.formatted_text, type: :text) if text_format?

        renderer.ok(raw_body(result.metadata, chunked_data || result.result_json), type: :json)
      end

      def buffered_chunks_response(call, watch, first_chunk)
        data = +first_chunk
        msg = next_buffered_message(call, watch)
        while msg.content == :result_chunk
          data << msg.result_chunk.data
          msg = next_buffered_message(call, watch)
        end

        finish(call)
        return query_error(msg.error.code, msg.error.message) if msg.content == :error

        result_response(msg.result, data)
      end

      # Nothing is sent to the caller while buffering, so failures map like the non-streamed path.
      def next_buffered_message(call, watch)
        next_stream_message(call, watch, accepted: BUFFERED_CONTENT)
      rescue StreamAborted
        raise ClientClosed if watch&.cancelled
        raise StreamFailure.new(TIMEOUT_MESSAGE, 504) if deadline_passed?

        raise StreamFailure.new(STREAM_ERROR_MESSAGE, 502)
      end

      def stream_response(call, watch, first_chunk)
        outer = renderer.stream_frame(type: text_format? ? :text : :json)
        body = StreamBody.new(
          context: @log_context,
          producer: ->(&out) { stream_chunks(call, watch, first_chunk, outer, &out) },
          closer: -> { close_stream(call, watch) }
        )
        response = Response.new(status: 200, content_type: outer.content_type, body: body)
        @streaming = true
        response
      end

      def stream_chunks(call, watch, chunk, outer, &)
        release_request_resources!
        yield outer.head + outer.encode(inner_frame(nil).head)
        loop do
          yield outer.encode(chunk)
          msg = next_stream_message(call, watch)
          return finish_stream(call, msg.result, outer, &) if msg.content == :result

          chunk = msg.result_chunk.data
        end
      end

      def finish_stream(call, result, outer)
        finish(call)
        yield outer.encode(inner_frame(result.metadata).tail) + outer.tail
        @stream_finished = true
      end

      def next_stream_message(call, watch, accepted: STREAM_CONTENT)
        msg, failure = read_stream_message(call, accepted)
        fail_stream(watch, failure) if failure

        msg
      end

      def read_stream_message(call, accepted)
        message = call.run_batch(recv_ops).message
        return [nil, final_status(call)] if message.nil?

        msg = ::Orbit::V1::ExecuteQueryMessage.decode(message)
        return [msg, nil] if accepted.include?(msg.content)

        [nil, msg.content == :error ? "#{msg.error.code}: #{msg.error.message}" : msg.content.inspect]
      rescue ::GRPC::Core::CallError => e
        [nil, e.message]
      rescue StandardError => e
        ::Gitlab::ErrorTracking.track_exception(e, user_id: user.id)
        [nil, e.message]
      end

      def final_status(call)
        status = call.run_batch(OPS::RECV_STATUS_ON_CLIENT => nil).status
        "#{status.code}: #{status.details}"
      end

      def fail_stream(watch, reason)
        unless watch&.cancelled
          metrics.increment_grpc_error('execute_query', 'result_stream')
          log_error('result_stream', reason)
        end

        raise StreamAborted, STREAM_ERROR_MESSAGE
      end

      def close_stream(call, watch)
        close_call(call, watch)
        observe_grpc(stream_outcome(watch))
      end

      def stream_outcome(watch)
        return 'ok' if @stream_finished

        watch&.cancelled ? 'cancelled' : 'error'
      end

      def inner_frame(metadata)
        Frame.split(Response.text(text_format? ? STREAM_SENTINEL : raw_body(metadata, STREAM_SENTINEL)))
      end

      def text_format?
        PROTO_FORMATS.key?(format)
      end

      def raw_body(metadata, raw)
        md = metadata || ::Orbit::V1::QueryMetadata.new
        strings = md.raw_query_strings.to_a

        payload = { result: raw.empty? ? '' : ::JSON::Fragment.new(raw), query_type: md.query_type }
        payload[:raw_query_strings] = strings if strings.any?
        payload[:row_count] = md.row_count
        ::Gitlab::Json.generate(payload)
      end

      def query_error(code, message, reason = nil)
        @failed = true
        renderer.query_error(code, message, reason)
      end

      def fail_query(message, http_status)
        log_error('fail_query', message)
        renderer.failure(message, http_status)
      end

      def initial_message
        ::Orbit::V1::ExecuteQueryMessage.new(
          request: ::Orbit::V1::ExecuteQueryRequest.new(
            query: params['Query'],
            format: PROTO_FORMATS.fetch(format, :RESPONSE_FORMAT_RAW),
            query_type: params['QueryType'] == 'named' ? :QUERY_TYPE_NAMED : :QUERY_TYPE_JSON,
            language: GrpcClient.query_language(params['Language']),
            chunked_result: true
          )
        )
      end

      def metadata
        GrpcClient.base_metadata.merge!(params.dig('GkgServer', 'headers').to_h)
      end

      def deadline
        @deadline ||= ::GRPC::Core::TimeConsts.from_relative_time(timeout_seconds)
      end

      def deadline_passed?
        Time.current >= deadline
      end

      def timeout_seconds
        @timeout_seconds ||= begin
          seconds = params['TimeoutSeconds'].to_i
          seconds = DEFAULT_TIMEOUT_SECONDS if seconds <= 0
          [seconds, MAX_TIMEOUT_SECONDS, rack_timeout_remaining].compact.min
        end
      end

      def rack_timeout_remaining
        info = env[::Rack::Timeout::ENV_INFO_KEY]
        return unless info&.timeout

        info.timeout - info.service.to_f - RACK_TIMEOUT_MARGIN_SECONDS
      end

      def release_request_resources!
        ::ActiveRecord::Base.connection_handler.connection_pool_list(:all).each do |pool|
          pool.release_connection unless pool.active_connection&.transaction_open?
        end
        env['puma.mark_as_io_bound']&.call
      end

      def observe_redaction(total:, filtered:, duration:)
        metrics.observe_redaction_duration(duration)
        metrics.observe_redaction_batch_size(total)
        metrics.observe_redaction_filtered(filtered)
      end

      def observe_grpc(status)
        metrics.observe_grpc_duration('execute_query', status, ::Gitlab::Metrics::System.monotonic_time - @start)
      end

      def metrics
        ::Gitlab::Metrics::KnowledgeGraph::Request
      end

      def log_error(event, message)
        ::Gitlab::KnowledgeGraph::Logger.build.error(
          message: "orbit query #{event}",
          ::Labkit::Fields::CLASS_NAME => self.class.name,
          ::Labkit::Fields::ERROR_MESSAGE => message,
          ::Labkit::Fields::GL_USER_ID => user.id
        )
      end
    end
  end
end
