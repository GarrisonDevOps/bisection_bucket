# frozen_string_literal: true

module Analytics
  module KnowledgeGraph
    class RequestContext < Data.define(:source_type, :session_id, :request_id, :user_agent, :token_type)
      # Orbit clients send the first; Workhorse sets the second for Duo Workflow sessions.
      SESSION_ID_HEADERS = %w[X-Orbit-Session-Id X-Duo-Workflow-Session-Id].freeze
      REQUEST_ID_HEADER = 'X-Orbit-Request-Id'

      TRACE_ID_PATTERN = /\A[A-Za-z0-9._-]{1,64}\z/

      # Group, project, and service account tokens are PATs; user_type separates their bot users from people.
      TOKEN_TYPES = {
        'PersonalAccessToken' => 'personal_access_token',
        'OauthAccessToken' => 'oauth_access_token',
        'Authn::Tokens::StatelessAccessToken' => 'oauth_access_token',
        'Authn::Tokens::IamOauthToken' => 'oauth_access_token'
      }.freeze

      VALID_SOURCE_TYPES = [
        SourceType::FRONTEND, SourceType::DWS, SourceType::MCP,
        SourceType::CORE, SourceType::REST, SourceType::CODE_INTELLIGENCE
      ].freeze

      def self.from_request(request, source_type: nil, access_token: nil)
        new(
          source_type: source_type,
          session_id: SESSION_ID_HEADERS.map { |header| request.headers[header] }.grep(TRACE_ID_PATTERN).first,
          request_id: request.headers[REQUEST_ID_HEADER],
          user_agent: request.user_agent,
          token_type: TOKEN_TYPES[access_token.class.name]
        )
      end

      def self.for_mcp_request(request, access_token: nil)
        oauth_access_token = access_token if access_token.is_a?(::OauthAccessToken)

        from_request(request,
          source_type: SourceType.for_mcp_request(request: request, oauth_access_token: oauth_access_token),
          access_token: access_token)
      end

      def initialize(source_type: nil, session_id: nil, request_id: nil, user_agent: nil, token_type: nil)
        super(source_type: validated_source_type(source_type), session_id: accepted_trace_id(session_id),
              request_id: accepted_trace_id(request_id), user_agent: user_agent, token_type: token_type)
      end

      private

      def accepted_trace_id(value)
        value&.slice(TRACE_ID_PATTERN)
      end

      def validated_source_type(source_type)
        return source_type if VALID_SOURCE_TYPES.include?(source_type)
        return SourceType::REST if source_type.nil?

        ::Gitlab::AppLogger.warn(
          "Invalid source_type for Orbit query: #{source_type.inspect}, falling back to 'rest'"
        )

        SourceType::REST
      end
    end
  end
end
