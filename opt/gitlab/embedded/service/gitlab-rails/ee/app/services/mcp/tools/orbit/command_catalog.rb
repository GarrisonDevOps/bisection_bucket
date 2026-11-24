# frozen_string_literal: true

module Mcp
  module Tools
    module Orbit
      module CommandCatalog
        CACHE_KEY = 'mcp_orbit_agent_commands'
        CACHE_EXPIRY = 10.minutes
        LIST_COMMANDS_TIMEOUT = 2

        def self.tools_for(context)
          return {} unless read_orbit_allowed?(context.access_token) &&
            ::Analytics::KnowledgeGraph.accessible_for?(context.current_user) &&
            ::Analytics::KnowledgeGraph::AuthorizationContext.for(context.current_user).has_enabled_namespaces?

          commands(context.current_user).to_h do |command|
            [command[:name], CommandTool.new(command: command, context: context)]
          end
        rescue ::Analytics::KnowledgeGraph::GrpcClient::ConnectionError,
          ::Analytics::KnowledgeGraph::GrpcClient::AuthorizationError => e
          ::Gitlab::KnowledgeGraph::Logger.build.error(
            message: 'MCP Orbit list_agent_commands error', ::Labkit::Fields::ERROR_MESSAGE => e.message
          )
          {}
        end

        def self.read_orbit_allowed?(access_token)
          ::Authz::Tokens::AuthorizeGranularScopesService.new(
            boundaries: ::Authz::Boundary.for(:user), permissions: :read_orbit, token: access_token
          ).execute.success?
        end
        private_class_method :read_orbit_allowed?

        def self.commands(current_user)
          # The Orbit server returns the same commands to every user. Only the query language changes the list.
          cache_key = [CACHE_KEY, ::Analytics::KnowledgeGraph::GrpcClient::DEFAULT_QUERY_LANGUAGE]

          Rails.cache.fetch(cache_key, expires_in: CACHE_EXPIRY, skip_nil: true) do
            ::Analytics::KnowledgeGraph::GrpcClient.new.list_agent_commands(
              user: current_user,
              timeout: LIST_COMMANDS_TIMEOUT,
              request_context: ::Analytics::KnowledgeGraph::RequestContext.new(
                source_type: ::Analytics::KnowledgeGraph::SourceType::MCP
              )
            ).then { |commands| commands.presence if commands.is_a?(Array) }
          end.to_a
        end
        private_class_method :commands
      end
    end
  end
end
