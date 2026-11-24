# frozen_string_literal: true

module API
  module Helpers
    module Mcp
      # The per-request `_meta` that MCP revision 2026-07-28 sends in place of the `initialize` handshake.
      # A request without it, or with a handshake revision, is a legacy request.
      # See: https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning
      class RequestMeta
        PROTOCOL_VERSION_KEY = 'io.modelcontextprotocol/protocolVersion'
        CLIENT_CAPABILITIES_KEY = 'io.modelcontextprotocol/clientCapabilities'

        class << self
          # @param rpc_params [Hash, Array, nil] the JSON-RPC `params` of the request
          # @return [API::Helpers::Mcp::RequestMeta]
          def from_jsonrpc_params(rpc_params)
            return new({}) unless rpc_params.is_a?(Hash)

            meta = rpc_params.with_indifferent_access[:_meta]
            new(meta.is_a?(Hash) ? meta : {})
          end
        end

        # @param meta [Hash] the `_meta` Hash, empty for a legacy request
        def initialize(meta)
          @meta = meta
        end

        # @return [String, nil]
        def protocol_version
          @meta[PROTOCOL_VERSION_KEY]
        end

        def modern?
          ::API::Mcp::Handlers::InitializeRequest::STATELESS_PROTOCOL_VERSIONS.include?(protocol_version)
        end

        def unsupported_protocol_version?
          return false if protocol_version.nil?

          ::API::Mcp::Handlers::InitializeRequest::SUPPORTED_PROTOCOL_VERSIONS.exclude?(protocol_version)
        end

        # An empty Hash counts as present: a client with no capabilities still declares that.
        def client_capabilities_missing?
          @meta[CLIENT_CAPABILITIES_KEY].nil?
        end
      end
    end
  end
end
