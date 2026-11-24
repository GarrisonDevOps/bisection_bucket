# frozen_string_literal: true

require 'orbit'
require 'resolv'

module Analytics
  module KnowledgeGraph
    class GrpcClient
      include ::Gitlab::Loggable

      MUTEX = Mutex.new
      DEFAULT_TIMEOUT = 10
      QUERY_LANGUAGES = { 'gql' => :QUERY_LANGUAGE_GQL }.freeze
      DEFAULT_QUERY_LANGUAGE = 'gql'
      DNS_RESOLUTION_TIMEOUT = 2
      DEFAULT_GRPC_ENDPOINT = 'localhost:50054'
      CHANNEL_ARGS = {
        'grpc.keepalive_time_ms' => 60_000,
        'grpc.keepalive_timeout_ms' => 20_000,
        'grpc.keepalive_permit_without_calls' => 1,
        'grpc.max_receive_message_length' => 8 * 1024 * 1024,
        'grpc.max_send_message_length' => 8 * 1024 * 1024
      }.freeze

      AuthorizationError = Class.new(StandardError)

      class ConnectionError < StandardError
        GENERIC_MESSAGE = 'Orbit request failed'
        CLIENT_ERROR_CODES = [
          GRPC::Core::StatusCodes::INVALID_ARGUMENT,
          GRPC::Core::StatusCodes::NOT_FOUND,
          GRPC::Core::StatusCodes::FAILED_PRECONDITION
        ].freeze

        attr_reader :grpc_code, :grpc_details

        def initialize(message, grpc_code: nil, grpc_details: nil)
          super(message)
          @grpc_code = grpc_code
          @grpc_details = grpc_details
        end

        def client_error?
          CLIENT_ERROR_CODES.include?(grpc_code)
        end
      end

      class << self
        def query_language(name = DEFAULT_QUERY_LANGUAGE)
          name = name.presence || DEFAULT_QUERY_LANGUAGE
          QUERY_LANGUAGES.fetch(name.to_s) { raise ArgumentError, "Unknown Orbit query language: #{name}" }
        end

        def stub(endpoint = nil)
          target = endpoint || configured_endpoint

          MUTEX.synchronize do
            @stubs ||= {}
            @stubs[target] ||= begin
              channel = create_channel(target)
              ::Orbit::V1::OrbitService::Stub.new(
                channel.target,
                nil,
                interceptors: client_interceptors,
                channel_override: channel
              )
            end
          end
        end

        def base_metadata
          metadata = { 'client_name' => Gitlab::Runtime.sidekiq? ? 'gitlab-sidekiq' : 'gitlab-web' }
          correlation_id = Labkit::Correlation::CorrelationId.current_id
          metadata['x-gitlab-correlation-id'] = correlation_id if correlation_id.present?
          metadata
        end

        def channel(endpoint = nil)
          target = endpoint || configured_endpoint

          MUTEX.synchronize { create_channel(target) }
        end

        def clear_stubs!
          MUTEX.synchronize do
            @channels&.each_value(&:close)
            @channels = nil
            @stubs = nil
          end
        end

        def configured_endpoint
          Gitlab.config.knowledge_graph.grpc_endpoint
        rescue Gitlab::Configs::MissingConfig
          fallback = ENV.fetch('KNOWLEDGE_GRAPH_GRPC_ENDPOINT', DEFAULT_GRPC_ENDPOINT)
          ::Gitlab::KnowledgeGraph::Logger.build.warn(
            message: 'Knowledge Graph gRPC endpoint not configured, using fallback',
            fallback_endpoint: fallback
          )
          fallback
        end

        def secure_channel?(target)
          uri = URI(target)
          uri.scheme == 'tls' || uri.scheme == 'dns+tls'
        rescue URI::InvalidURIError
          false
        end

        def private_address?(target)
          host = extract_host(target)
          return true if host == 'localhost'

          ips = resolve_ips(host)
          ips.any? && ips.all? { |ip| private_ip?(ip) }
        end

        # Returns a hash of gRPC metadata headers to be forwarded to the Orbit
        # service. This generic map is the single source of truth for all
        # per-call metadata other than the keys listed below, which are
        # managed per-call by `auth_metadata` / `QueryRunner.params_for`:
        #
        #   RESERVED (do not add here):
        #     - `authorization`            (per-call JWT)
        #     - `client_name`, `x-gitlab-correlation-id` (`base_metadata`)
        #
        # Currently includes:
        # - `x-gitlab-enabled-feature-flags` (SaaS only) - comma-separated list
        #   of enabled flag names, mirroring `Gitlab::AiGateway#public_headers`.
        # - `x-gitlab-enabled-instance-verbose-ai-logs` (self-hosted) - boolean
        #   string sourced from `ApplicationSetting#enabled_instance_verbose_ai_logs`.
        #
        # Called from `auth_metadata` and `QueryRunner.params_for`
        # so that every Orbit call receives the same metadata.
        def outgoing_headers
          headers = {}

          flags = enabled_feature_flags_for_orbit
          headers['x-gitlab-enabled-feature-flags'] = flags.join(',') if flags.any?

          verbose_ai_logs = ::Gitlab::CurrentSettings.enabled_instance_verbose_ai_logs&.to_s
          headers['x-gitlab-enabled-instance-verbose-ai-logs'] = verbose_ai_logs if verbose_ai_logs.present?

          headers
        end

        private

        # SaaS-only. Mirrors `Gitlab::AiGateway.expanded_ai_logging_on_self_managed?`
        # behaviour: the `x-gitlab-enabled-feature-flags` header is only
        # populated on gitlab.com. Self-managed instances rely on the instance
        # setting (`x-gitlab-enabled-instance-verbose-ai-logs`) instead.
        def enabled_feature_flags_for_orbit
          return [] unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

          flags = []
          flags << 'verbose_gkg_logs' if Feature.enabled?(:gkg_verbose_logs) # rubocop:disable Gitlab/FeatureFlagWithoutActor -- instance-scoped ops flag
          flags
        end

        def private_ip?(ip)
          addr = IPAddr.new(ip)
          addr.loopback? || addr.private?
        rescue IPAddr::InvalidAddressError
          false
        end

        def resolve_ips(host)
          IPAddr.new(host)
          [host]
        rescue IPAddr::InvalidAddressError
          resolver = Resolv::DNS.new
          resolver.timeouts = DNS_RESOLUTION_TIMEOUT
          begin
            resolver.getaddresses(host).map(&:to_s)
          rescue Resolv::ResolvError, Resolv::ResolvTimeout
            []
          ensure
            resolver.close
          end
        end

        # Not thread-safe on its own. Callers hold MUTEX.
        def create_channel(target)
          @channels ||= {}
          @channels[target] ||= GRPC::ClientStub.setup_channel(
            nil, strip_scheme(target), channel_credentials(target), CHANNEL_ARGS.dup
          )
        end

        def channel_credentials(target)
          uri = URI(target)

          if uri.scheme == 'tls' || uri.scheme == 'dns+tls'
            GRPC::Core::ChannelCredentials.new(::Gitlab::X509::Certificate.ca_certs_bundle)
          else
            :this_channel_is_insecure
          end
        rescue URI::InvalidURIError
          :this_channel_is_insecure
        end

        def strip_scheme(target)
          target.sub(%r{^tcp://|^tls://}, '').sub(%r{^dns\+tls:}, 'dns:')
        end

        def extract_host(target)
          uri = URI(target)
          uri.host || target.split(':').first
        rescue URI::InvalidURIError
          target.split(':').first
        end

        def client_interceptors
          interceptors = []
          interceptors << Labkit::Tracing::GRPC::ClientInterceptor.instance if Labkit::Tracing.enabled?
          interceptors
        end
      end

      def initialize(endpoint: nil)
        @endpoint = endpoint
      end

      def list_tools(
        user:, timeout: DEFAULT_TIMEOUT, request_context: RequestContext.new,
        language: DEFAULT_QUERY_LANGUAGE
      )
        raise ArgumentError, 'user is required' unless user

        request = ::Orbit::V1::ListToolsRequest.new(language: self.class.query_language(language))
        kwargs = request_kwargs(user: user, timeout: timeout, request_context: request_context)

        measure_grpc('list_tools') do
          response = stub.list_tools(request, **kwargs)

          response.tools.map do |tool|
            {
              name: tool.name,
              description: tool.description,
              parameters: safe_json_parse(tool.parameters_json_schema)
            }
          end
        end
      rescue GRPC::BadStatus => e
        handle_grpc_error('list_tools', e)
      end

      def list_agent_commands(
        user:, command_names: [], format: :raw, timeout: DEFAULT_TIMEOUT,
        request_context: RequestContext.new, language: DEFAULT_QUERY_LANGUAGE
      )
        raise ArgumentError, 'user is required' unless user

        proto_format = format == :llm ? :RESPONSE_FORMAT_LLM : :RESPONSE_FORMAT_RAW
        request = ::Orbit::V1::ListAgentCommandsRequest.new(
          command_names: command_names, format: proto_format, language: self.class.query_language(language)
        )
        kwargs = request_kwargs(user: user, timeout: timeout, request_context: request_context)

        measure_grpc('list_agent_commands') do
          response = stub.list_agent_commands(request, **kwargs)

          if response.respond_to?(:formatted_text) && response.formatted_text.present?
            { formatted_text: response.formatted_text }
          else
            response.commands.map do |command|
              {
                name: command.name,
                description: command.description,
                parameters: safe_json_parse(command.parameters_json_schema)
              }
            end
          end
        end
      rescue GRPC::BadStatus => e
        handle_grpc_error('list_agent_commands', e)
      end

      def invoke_agent_command(
        command_name:, parameters:, user:, timeout: DEFAULT_TIMEOUT,
        request_context: RequestContext.new, language: DEFAULT_QUERY_LANGUAGE
      )
        raise ArgumentError, 'user is required' unless user

        request = ::Orbit::V1::InvokeAgentCommandRequest.new(
          command_name: command_name,
          parameters_json: parameters.to_json,
          language: self.class.query_language(language)
        )
        kwargs = request_kwargs(user: user, timeout: timeout, request_context: request_context)

        measure_grpc('invoke_agent_command') do
          response = stub.invoke_agent_command(request, **kwargs)

          case response.content
          when :result_json
            safe_json_parse(response.result_json)
          when :formatted_text
            { formatted_text: response.formatted_text }
          else
            {}
          end
        end
      rescue GRPC::BadStatus => e
        handle_grpc_error('invoke_agent_command', e)
      end

      def get_graph_schema(
        user:, expand_nodes: [], timeout: DEFAULT_TIMEOUT,
        request_context: RequestContext.new
      )
        raise ArgumentError, 'user is required' unless user

        request = ::Orbit::V1::GetGraphSchemaRequest.new(
          expand_nodes: expand_nodes,
          format: :RESPONSE_FORMAT_RAW
        )
        kwargs = request_kwargs(user: user, timeout: timeout, request_context: request_context)

        measure_grpc('get_graph_schema') do
          response = stub.get_graph_schema(request, **kwargs)

          case response.content
          when :structured
            map_structured_schema(response.structured)
          else
            {}
          end
        end
      rescue GRPC::BadStatus => e
        handle_grpc_error('get_graph_schema', e)
      end

      def list_skills(
        user:, timeout: DEFAULT_TIMEOUT, request_context: RequestContext.new,
        language: DEFAULT_QUERY_LANGUAGE
      )
        raise ArgumentError, 'user is required' unless user

        request = ::Orbit::V1::ListSkillsRequest.new(language: self.class.query_language(language))
        kwargs = request_kwargs(user: user, timeout: timeout, request_context: request_context)

        measure_grpc('list_skills') do
          response = stub.list_skills(request, **kwargs)

          {
            'skills' => response.skills.map do |skill|
              {
                'name' => skill.name,
                'version' => skill.version,
                'description' => skill.description,
                'compatibility' => skill.compatibility
              }
            end,
            'server_version' => response.server_version
          }
        end
      rescue GRPC::BadStatus => e
        handle_grpc_error('list_skills', e)
      end

      def get_skill(
        name:, user:, metadata_only: false, timeout: DEFAULT_TIMEOUT,
        request_context: RequestContext.new, language: DEFAULT_QUERY_LANGUAGE
      )
        raise ArgumentError, 'user is required' unless user

        request = ::Orbit::V1::GetSkillRequest.new(
          name: name, metadata_only: metadata_only, language: self.class.query_language(language)
        )
        kwargs = request_kwargs(user: user, timeout: timeout, request_context: request_context)

        measure_grpc('get_skill') do
          response = stub.get_skill(request, **kwargs)

          {
            'name' => response.name,
            'version' => response.version,
            'compatibility' => response.compatibility,
            'server_version' => response.server_version,
            'files' => response.files.map do |file|
              {
                'path' => file.path,
                'sha256' => file.sha256,
                'content' => file.content
              }
            end
          }
        end
      rescue GRPC::BadStatus => e
        handle_grpc_error('get_skill', e)
      end

      def list_named_queries(
        user:, timeout: DEFAULT_TIMEOUT,
        request_context: RequestContext.new, language: DEFAULT_QUERY_LANGUAGE
      )
        raise ArgumentError, 'user is required' unless user

        request = ::Orbit::V1::ListNamedQueriesRequest.new(language: self.class.query_language(language))
        kwargs = request_kwargs(user: user, timeout: timeout, request_context: request_context)

        measure_grpc('list_named_queries') do
          response = stub.list_named_queries(request, **kwargs)

          response.queries.map do |query|
            {
              name: query.name,
              description: query.description,
              raw_query: query.raw_query
            }
          end
        end
      rescue GRPC::BadStatus => e
        handle_grpc_error('list_named_queries', e)
      end

      def get_cluster_health(
        user:, timeout: DEFAULT_TIMEOUT,
        request_context: RequestContext.new
      )
        raise ArgumentError, 'user is required' unless user

        request = ::Orbit::V1::GetClusterHealthRequest.new(format: :RESPONSE_FORMAT_RAW)
        kwargs = request_kwargs(user: user, timeout: timeout, request_context: request_context)

        response = measure_grpc('get_cluster_health') { stub.get_cluster_health(request, **kwargs) }

        case response.content
        when :structured
          structured = response.structured
          {
            status: cluster_status_to_string(structured.status),
            timestamp: structured.timestamp,
            version: structured.version,
            components: structured.components.map { |c| component_to_hash(c) }
          }
        else
          { status: 'unknown' }
        end
      rescue GRPC::BadStatus => e
        log_error('get_cluster_health', error: e.message, grpc_code: e.code)
        { status: 'unknown', error: 'Service unreachable' }
      end

      def get_indexing_status(
        user:, traversal_paths:, timeout: DEFAULT_TIMEOUT,
        request_context: RequestContext.new
      )
        raise ArgumentError, 'user is required' unless user

        request = ::Orbit::V1::GetIndexingStatusRequest.new(traversal_paths: traversal_paths)
        kwargs = request_kwargs(user: user, timeout: timeout, request_context: request_context)

        measure_grpc('get_indexing_status') do
          response = stub.get_indexing_status(request, **kwargs)

          {
            statuses: response.statuses.map do |status|
              projects = status.domains.find(&:projects)&.projects

              {
                traversal_path: status.traversal_path,
                phase: indexing_phase_to_string(status.phase),
                last_completed_at: parse_time(status.last_completed_at),
                projects: projects && map_projects_status(projects),
                domains: status.domains.map do |domain|
                  { name: domain.name, phase: indexing_phase_to_string(domain.phase) }
                end
              }
            end
          }
        end
      rescue GRPC::BadStatus => e
        handle_grpc_error('get_indexing_status', e)
      end

      def get_item_counts(
        user:, traversal_paths:, timeout: DEFAULT_TIMEOUT,
        request_context: RequestContext.new
      )
        raise ArgumentError, 'user is required' unless user

        single_path = traversal_paths.first if traversal_paths.one?
        request = ::Orbit::V1::GetItemCountsRequest.new(
          **(single_path ? { traversal_path: single_path } : { traversal_paths: traversal_paths })
        )
        kwargs = request_kwargs(user: user, timeout: timeout, request_context: request_context)

        measure_grpc('get_item_counts') do
          response = stub.get_item_counts(request, **kwargs)
          namespaces = response.namespaces.map { |namespace| [namespace.traversal_path, namespace.domains] }
          namespaces = [[single_path, response.domains]] if single_path

          {
            namespaces: namespaces.map do |traversal_path, domains|
              {
                traversal_path: traversal_path,
                domains: domains.map do |domain|
                  {
                    name: domain.name,
                    entities: domain.entities.map { |entity| { name: entity.name, count: entity.count } }
                  }
                end
              }
            end
          }
        end
      rescue GRPC::BadStatus => e
        handle_grpc_error('get_item_counts', e)
      end

      private

      def stub
        self.class.stub(@endpoint)
      end

      def request_kwargs(user:, timeout: DEFAULT_TIMEOUT, request_context: RequestContext.new)
        {
          metadata: auth_metadata(user: user, request_context: request_context),
          deadline: build_deadline(timeout)
        }
      end

      def auth_metadata(user:, request_context: RequestContext.new)
        target = @endpoint || self.class.configured_endpoint
        metadata = self.class.base_metadata

        auth_header = JwtAuth.authorization_header(user: user, request_context: request_context)
        raise AuthorizationError, 'Failed to generate authorization header' unless auth_header

        if self.class.secure_channel?(target) || self.class.private_address?(target)
          metadata['authorization'] = auth_header
        else
          log_error('auth_metadata', message: 'Skipping authorization header on insecure non-private channel',
            target: target)
        end

        metadata['x-client-user-agent'] = request_context.user_agent if request_context.user_agent.present?

        metadata.merge!(self.class.outgoing_headers)

        metadata
      end

      def build_deadline(timeout)
        GRPC::Core::TimeConsts.from_relative_time(timeout)
      end

      def measure_grpc(method)
        start = ::Gitlab::Metrics::System.monotonic_time
        result = yield
        status = 'ok'
        result
      rescue StandardError
        status = 'error'
        raise
      ensure
        duration = ::Gitlab::Metrics::System.monotonic_time - start
        request_metrics.observe_grpc_duration(method, status || 'error', duration)
      end

      def request_metrics
        ::Gitlab::Metrics::KnowledgeGraph::Request
      end

      def handle_grpc_error(rpc_name, error, extra = {})
        request_metrics.increment_grpc_error(rpc_name, error.code.to_s)
        log_error(rpc_name, **extra.merge(error: error.message, grpc_code: error.code))
        raise ConnectionError.new(
          "#{rpc_name} failed: #{error.message} (#{error.code})",
          grpc_code: error.code,
          grpc_details: error.details
        )
      end

      def safe_json_parse(json_string)
        return {} if json_string.blank?

        result = ::Gitlab::Json.safe_parse(json_string)
        return result if result

        log_error('json_parse', input_truncated: json_string.truncate(200))
        {}
      end

      def cluster_status_to_string(status)
        case status
        when :CLUSTER_STATUS_HEALTHY then 'healthy'
        when :CLUSTER_STATUS_DEGRADED then 'degraded'
        when :CLUSTER_STATUS_UNHEALTHY then 'unhealthy'
        when :CLUSTER_STATUS_MIGRATING then 'migrating'
        else 'unknown'
        end
      end

      def component_to_hash(component)
        {
          name: component.name,
          status: cluster_status_to_string(component.status),
          replicas: {
            ready: component.replicas&.ready || 0,
            desired: component.replicas&.desired || 0
          },
          metrics: component.metrics.to_h
        }
      end

      def map_structured_schema(structured)
        {
          schema_version: structured.schema_version,
          domains: structured.domains.map { |d| schema_domain_to_hash(d) },
          nodes: structured.nodes.map { |n| schema_node_to_hash(n) },
          edges: structured.edges.map { |e| schema_edge_to_hash(e) }
        }
      end

      def schema_domain_to_hash(domain)
        {
          name: domain.name,
          description: domain.description,
          node_names: domain.node_names.to_a
        }
      end

      def schema_node_to_hash(node)
        hash = {
          name: node.name,
          domain: node.domain,
          description: node.description,
          primary_key: node.primary_key,
          label_field: node.label_field
        }

        if node.properties.any?
          hash[:properties] = node.properties.map { |p| schema_property_to_hash(p) }
          hash[:style] = { size: node.style&.size || 30, color: node.style&.color || '#64748B' }
          hash[:outgoing_edges] = node.outgoing_edges.to_a
          hash[:incoming_edges] = node.incoming_edges.to_a
        end

        hash
      end

      def schema_property_to_hash(property)
        {
          name: property.name,
          data_type: property.data_type,
          nullable: property.nullable,
          enum_values: property.enum_values.to_a,
          text_searchable: property.has_text_searchable? ? property.text_searchable : nil,
          default_column: property.has_default_column? ? property.default_column : nil
        }
      end

      def schema_edge_to_hash(edge)
        {
          name: edge.name,
          description: edge.description,
          variants: edge.variants.map { |v| { source_type: v.source_type, target_type: v.target_type } }
        }
      end

      def parse_time(value)
        Time.iso8601(value) if value.present?
      rescue ArgumentError
        nil
      end

      def map_projects_status(projects)
        {
          indexed: projects.indexed,
          total_known: projects.total_known,
          gaps: projects.gaps
        }
      end

      def indexing_phase_to_string(phase)
        case phase
        when :INDEXING_PHASE_NOT_STARTED then 'not_started'
        when :INDEXING_PHASE_SYNCING then 'syncing'
        when :INDEXING_PHASE_READY then 'ready'
        when :INDEXING_PHASE_ERROR then 'error'
        else 'unknown'
        end
      end

      def logger
        @logger ||= ::Gitlab::KnowledgeGraph::Logger.build
      end

      def log_error(rpc_name, **payload)
        logger.error(
          build_structured_payload(
            **payload.merge(
              message: "KnowledgeGraph::GrpcClient #{rpc_name} failed"
            )
          )
        )
      end
    end
  end
end
