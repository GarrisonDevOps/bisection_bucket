# frozen_string_literal: true

module Analytics
  module KnowledgeGraph
    class SourceType
      FRONTEND = 'frontend'
      DWS = 'dws'
      MCP = 'mcp'
      CORE = 'core' # Reserved for internal service calls (not yet implemented)
      REST = 'rest'
      CODE_INTELLIGENCE = 'code_intelligence'
      AI_WORKFLOWS_SCOPE = 'ai_workflows'

      FRONTEND_SUBTYPES = [CODE_INTELLIGENCE].freeze

      class << self
        def for_orbit_request(request:, oauth_access_token: nil, frontend_subtype: nil)
          if frontend_request?(request)
            return frontend_subtype if frontend_subtype && FRONTEND_SUBTYPES.include?(frontend_subtype)

            return FRONTEND
          end

          return DWS if ai_workflows_token?(oauth_access_token)

          REST
        end

        def for_mcp_request(request:, oauth_access_token: nil)
          return MCP unless oauth_access_token

          resolved = for_orbit_request(request: request, oauth_access_token: oauth_access_token)
          return resolved if resolved == DWS

          MCP
        end

        def frontend_request?(request)
          return false unless request&.env&.include?('HTTP_X_CSRF_TOKEN')
          return false unless request.session&.include?(:_csrf_token)

          # RequestForgeryProtection skips CSRF verification for safe verbs like GET/HEAD,
          # but Orbit browser/dashboard requests are POSTs that carry a session CSRF token.
          # Force POST while classifying the current request so Rails performs the same
          # token verification it would for the real browser call.
          #
          # This classification only affects billing metadata. In the worst case, a non-browser
          # client that happens to send a stale CSRF header matching a session token could be
          # misclassified as `frontend`; it does not grant access or weaken request security.
          Gitlab::RequestForgeryProtection.verified?(request.env.merge('REQUEST_METHOD' => 'POST'))
        end

        def ai_workflows_token?(oauth_access_token)
          oauth_access_token&.scopes&.include?(AI_WORKFLOWS_SCOPE)
        end
      end
    end
  end
end
