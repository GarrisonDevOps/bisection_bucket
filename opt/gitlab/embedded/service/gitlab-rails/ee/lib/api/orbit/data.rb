# frozen_string_literal: true

module API
  module Orbit
    class Data < ::API::Base
      include ::API::Concerns::AiWorkflowsAccess
      include ::API::Helpers::HeadersHelpers
      include APIGuard

      helpers ::API::Orbit::QueryResponseHelpers

      feature_category :knowledge_graph
      urgency :low

      GRPC_CODE_TO_HTTP_STATUS = {
        ::GRPC::Core::StatusCodes::DEADLINE_EXCEEDED => 504,
        ::GRPC::Core::StatusCodes::PERMISSION_DENIED => 404,
        ::GRPC::Core::StatusCodes::INVALID_ARGUMENT => 400,
        ::GRPC::Core::StatusCodes::NOT_FOUND => 404,
        ::GRPC::Core::StatusCodes::UNAVAILABLE => 503
      }.freeze
      GRPC_DEFAULT_HTTP_STATUS = 500
      GRPC_CODE_HEADER = 'X-GKG-Grpc-Code'
      GRPC_ERROR_MESSAGE = ::Analytics::KnowledgeGraph::GrpcClient::ConnectionError::GENERIC_MESSAGE
      SKILL_CACHE_CONTROL = 'private, max-age=0, must-revalidate'

      # Although this API endpoint responds to POST requests, it is a read-only operation
      allow_access_with_scope :read_api
      allow_ai_workflows_access

      before do
        authenticate!

        unless route.settings[:skip_orbit_entitlement]
          not_found! unless ::Analytics::KnowledgeGraph.enabled_for?(current_user)

          forbidden! unless ::Analytics::KnowledgeGraph::OrbitLicense.available_for?(current_user)
        end
      end

      helpers do
        def source_type(frontend_subtype: nil)
          ::Analytics::KnowledgeGraph::SourceType.for_orbit_request(
            request: request,
            oauth_access_token: access_token.is_a?(OauthAccessToken) ? access_token : nil,
            frontend_subtype: frontend_subtype
          )
        end

        def orbit_response_format
          params[:response_format].to_sym
        end

        def grpc_client
          @grpc_client ||= ::Analytics::KnowledgeGraph::GrpcClient.new
        end

        include ::Analytics::Orbit::TargetResolver

        def require_enabled_namespaces!
          context = ::Analytics::KnowledgeGraph::AuthorizationContext.for(current_user)
          forbidden!('No Orbit enabled namespaces available') unless context.has_enabled_namespaces?
        end

        def orbit_enabled_root?(target)
          ::Analytics::KnowledgeGraph::AuthorizationContext.for(current_user)
            .enabled_root_namespace?(target.root_ancestor.id)
        end

        def orbit_request_context(resolved_source_type = source_type)
          ::Analytics::KnowledgeGraph::RequestContext.from_request(
            request, source_type: resolved_source_type, access_token: access_token
          )
        end

        def present_orbit_context(context, format)
          return present context, with: ::API::Entities::Orbit::Context unless format == :llm

          env['api.format'] = :txt
          content_type 'text/plain; charset=utf-8'
          body ::Analytics::Orbit::ContextLlmFormatter.new(context).execute
        end

        def require_skills_available!
          skills_available = ::Analytics::KnowledgeGraph.service_configured? &&
            ::Analytics::KnowledgeGraph::AuthorizationContext.for(current_user).has_enabled_namespaces?

          render_api_error!('Skills are not available', 404) unless skills_available
        end

        def fetch_skill(metadata_only: false)
          grpc_client.get_skill(
            name: params[:name],
            metadata_only: metadata_only,
            user: current_user,
            request_context: orbit_request_context
          )
        rescue ::Analytics::KnowledgeGraph::GrpcClient::ConnectionError => e
          render_api_error!('Skills are not available', 404) if e.grpc_code == ::GRPC::Core::StatusCodes::UNIMPLEMENTED
          raise unless e.grpc_code == ::GRPC::Core::StatusCodes::NOT_FOUND

          render_api_error!(e.grpc_details.presence || 'Skill not found', 404)
        end

        def skill_collection_etag(skills)
          pairs = skills.map { |skill| [skill['name'], skill['version']] }.sort
          %("#{Digest::SHA256.hexdigest(Gitlab::Json.generate(pairs))}")
        end

        def skill_etag(skill)
          %("#{skill['version']}")
        end

        def set_skill_cache_headers!(skill)
          header 'ETag', skill_etag(skill)
          header 'Cache-Control', SKILL_CACHE_CONTROL
        end

        def skill_etag_matches?(etag)
          validators = headers['If-None-Match'].to_s.split(',').map(&:strip)
          validators.include?('*') || validators.any? { |candidate| candidate.delete_prefix('W/') == etag }
        end

        def present_orbit_grep(grep)
          return present grep, with: ::API::Entities::Orbit::Grep unless orbit_response_format == :llm

          env['api.format'] = :txt
          content_type 'text/plain; charset=utf-8'
          body ::Analytics::Orbit::GrepLlmFormatter.new(grep).execute
        end
      end

      rescue_from ::Analytics::KnowledgeGraph::GrpcClient::AuthorizationError do
        error!('503 Service Unavailable', 503)
      end

      rescue_from ::Analytics::KnowledgeGraph::GoverningNamespaceGuard::RequiredError do |e|
        error!(e.contract.as_json, 422)
      end

      rescue_from ::Analytics::KnowledgeGraph::GrpcClient::ConnectionError do |e|
        status = GRPC_CODE_TO_HTTP_STATUS.fetch(e.grpc_code, GRPC_DEFAULT_HTTP_STATUS)
        error!({ code: e.grpc_code, message: GRPC_ERROR_MESSAGE }, status, { GRPC_CODE_HEADER => e.grpc_code.to_s })
      end

      namespace :orbit do
        desc 'Search for graph entities' do
          detail 'Searches for readable entities in an Orbit namespace or project.'
          tags %w[orbit]
          hidden true
          success code: 200, model: ::API::Entities::Orbit::Grep
          failure [
            { code: 400, message: 'Bad request' },
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' }
          ]
        end
        params do
          requires :search, type: String, allow_blank: false, desc: 'Search terms'
          optional :namespace_id, type: Integer, desc: 'Namespace (group) ID'
          optional :project_id, type: Integer, desc: 'Project ID'
          optional :full_path, type: String, limit: 255, desc: 'Full path of a project or group'
          optional :response_format, type: String, values: %w[raw llm], default: 'raw',
            desc: 'Response format: raw or llm'
          optional :limit, type: Integer, values: 1..50, default: 20, desc: 'Maximum number of results'
          optional :per_scope, type: Integer, values: 1..10, default: 5, desc: 'Maximum results per scope'
          optional :scopes, type: Array[String],
            coerce_with: ->(value) {
              ::Analytics::Orbit::GrepService.normalize_scopes(
                ::API::Validations::Types::CommaSeparatedToArray.coerce.call(value)
              )
            },
            values: ::Analytics::Orbit::GrepService::SCOPE_DEFINITIONS.keys,
            desc: 'Scopes to search. Accepts aliases such as mr, issue, comment, and branch.'
          exactly_one_of :namespace_id, :project_id, :full_path
        end
        # Grep runs the same searches as /search, so a token also needs use_global_search.
        route_setting :authorization, permissions: [:read_orbit, :use_global_search], boundary_type: :user
        route_setting :lifecycle, :experiment
        get :grep do
          search = params[:search].strip
          bad_request!('search must contain between 2 and 256 bytes') unless search.bytesize.between?(2, 256)
          bad_request!('per_scope cannot exceed limit') if params[:per_scope] > params[:limit]
          bad_request!('scopes cannot be empty') if params.key?(:scopes) && params[:scopes].blank?

          check_orbit_query_rate_limit!
          check_rate_limit!(
            :search_rate_limit,
            scope: { user: current_user },
            users_allowlist: Gitlab::CurrentSettings.current_application_settings.search_rate_limit_allowlist
          )
          require_enabled_namespaces!

          context = resolve_graph_status_context(params)
          not_found!('Namespace') unless context

          target = context[:target]
          ability = target.is_a?(Project) ? :read_project : :read_group
          not_found!('Namespace') unless can?(current_user, ability, target)
          not_found!('Namespace') unless orbit_enabled_root?(target)

          grep = ::Analytics::Orbit::GrepService.new(
            target,
            current_user: current_user,
            search: search,
            limit: params[:limit],
            per_scope: params[:per_scope],
            scopes: params[:scopes] || ::Analytics::Orbit::GrepService::DEFAULT_SCOPES,
            access_token: access_token
          ).execute
          present_orbit_grep(grep)
        rescue ::Analytics::Orbit::GrepService::AbusiveSearchError => e
          bad_request!(e.message)
        end

        desc 'Execute a query' do
          detail 'Executes a query against the Orbit gRPC service.'
          success code: 200, schema: 'orbit/query_response'
          tags %w[orbit]
        end
        params do
          requires :query, type: String, desc: 'GQL query text'
          optional :response_format, type: String, values: %w[raw llm gql],
            default: 'raw', desc: 'Response format: raw, llm, or gql'
          optional :source_type, type: String, desc: 'Optional frontend source subtype (e.g. code_intelligence)'
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_orbit, boundary_type: :user
        post :query do
          check_orbit_query_rate_limit!
          require_enabled_namespaces!

          render_orbit_query!(
            query: declared_params[:query],
            user: current_user,
            format: orbit_response_format,
            request_context: orbit_request_context(source_type(frontend_subtype: params[:source_type]))
          )
        end

        desc 'Execute a named query' do
          detail 'Executes a server-defined named query against the Orbit gRPC service. ' \
            'Requires a JSON request body: form encoding stringifies nested parameter values, ' \
            'which the per-query parameter schemas reject.'
          success code: 200, schema: 'orbit/query_response'
          tags %w[orbit]
        end
        params do
          requires :name, type: String, desc: 'Named query identifier'
          optional :parameters, type: Hash, default: {}, desc: 'Named query parameters'
          optional :response_format, type: String, values: %w[raw llm gql],
            default: 'raw', desc: 'Response format: raw, llm, or gql'
          optional :source_type, type: String, desc: 'Optional frontend source subtype (e.g. code_intelligence)'
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_orbit, boundary_type: :user
        post 'query/:name' do
          unless request.media_type == 'application/json'
            bad_request!('JSON request body required (Content-Type: application/json)')
          end

          check_orbit_query_rate_limit!

          require_enabled_namespaces!

          render_orbit_query!(
            query: {
              name: declared_params[:name],
              parameters: declared_params[:parameters]
            }.to_json,
            query_type: :named,
            user: current_user,
            format: orbit_response_format,
            request_context: orbit_request_context(source_type(frontend_subtype: params[:source_type]))
          )
        end

        desc 'Get entity context' do
          detail 'Resolves one Orbit token to a PostgreSQL summary and, optionally, its graph neighborhood. ' \
            'Requests that reach token resolution count against the orbit_query rate limit; with expand, they run at ' \
            'most one billable graph query. Requires a JSON request body.'
          success code: 200, model: ::API::Entities::Orbit::Context
          failure [
            { code: 400, message: 'Bad request' },
            { code: 401, message: 'Unauthorized' },
            { code: 403, message: 'Forbidden' },
            { code: 404, message: 'Not found' },
            { code: 429, message: 'Too many requests' }
          ]
          tags %w[orbit]
        end
        params do
          requires :tokens, type: Array[String], coerce_with: ->(tokens) { tokens },
            desc: 'Exactly one token: Type[id], a GID, an instance URL, path!iid, path#iid, path&iid (epic), ' \
              'or path@ref (branch or commit)'
          optional :expand, types: [TrueClass, FalseClass], default: false, documentation: { type: 'Boolean' },
            desc: 'Attach the graph neighborhood of the entity'
          optional :response_format, type: String, values: %w[raw llm],
            default: 'raw', desc: 'Response format: raw or llm'
        end
        route_setting :tier, :premium
        route_setting :authorization, permissions: :read_orbit, boundary_type: :user
        route_setting :lifecycle, :experiment
        route_setting :log_safety, { unsafe: %w[tokens] }
        post :context do
          unless request.media_type == 'application/json'
            bad_request!('JSON request body required (Content-Type: application/json)')
          end

          tokens = params[:tokens]
          bad_request!('tokens must be an array of exactly one string') unless
            tokens.is_a?(Array) && tokens.one? && tokens.first.is_a?(String)

          check_orbit_query_rate_limit!
          require_enabled_namespaces!

          status 200
          format = orbit_response_format
          context = ::Analytics::Orbit::ContextService.new(
            current_user,
            tokens.first,
            expand: params[:expand],
            format: format,
            request_context: orbit_request_context(source_type),
            env: env,
            access_token: access_token
          ).execute

          present_orbit_context(context, format)
        end

        desc 'List deployed Orbit skills' do
          detail 'Lists the Orbit skills deployed with the connected knowledge graph service.'
          success code: 200, model: ::API::Entities::Orbit::SkillCollection
          failure [
            { code: 401, message: 'Unauthorized' },
            { code: 404, message: 'Skills are not available' }
          ]
          tags %w[orbit]
        end
        route_setting :authorization, permissions: :read_orbit, boundary_type: :user
        route_setting :skip_orbit_entitlement, true
        get :skills do
          require_skills_available!
          check_orbit_query_rate_limit!

          result = grpc_client.list_skills(
            user: current_user,
            request_context: orbit_request_context
          )
          etag = skill_collection_etag(result['skills'])
          header 'ETag', etag
          header 'Cache-Control', SKILL_CACHE_CONTROL
          not_modified! if skill_etag_matches?(etag)

          present result, with: ::API::Entities::Orbit::SkillCollection
        rescue ::Analytics::KnowledgeGraph::GrpcClient::ConnectionError => e
          raise unless e.grpc_code == ::GRPC::Core::StatusCodes::UNIMPLEMENTED

          render_api_error!('Skills are not available', 404)
        end

        desc 'Retrieve a deployed Orbit skill' do
          detail 'Retrieves a complete deployed Orbit skill tree. HEAD requests retrieve only skill metadata.'
          success code: 200, model: ::API::Entities::Orbit::Skill
          failure [
            { code: 401, message: 'Unauthorized' },
            { code: 404, message: 'Skill not found or skills are not available' }
          ]
          tags %w[orbit]
        end
        params do
          requires :name, type: String, regexp: /\A[a-z0-9][a-z0-9-]*\z/, desc: 'Deployed skill name'
        end
        route_setting :authorization, permissions: :read_orbit, boundary_type: :user
        route_setting :skip_orbit_entitlement, true
        get 'skills/:name' do
          require_skills_available!
          check_orbit_query_rate_limit!

          if request.head? || headers['If-None-Match'].present?
            metadata = fetch_skill(metadata_only: true)
            etag = skill_etag(metadata)
            set_skill_cache_headers!(metadata)

            not_modified! if skill_etag_matches?(etag)
            body '' if request.head?
          end

          unless request.head?
            # A stale validator deliberately costs one metadata call before this full-tree cache miss.
            result = fetch_skill
            set_skill_cache_headers!(result)

            present result, with: ::API::Entities::Orbit::Skill
          end
        end

        desc 'Retrieve a deployed Orbit skill file' do
          detail 'Retrieves a UTF-8 file from a deployed Orbit skill as raw text.'
          produces %w[text/markdown text/plain]
          success code: 200
          failure [
            { code: 401, message: 'Unauthorized' },
            { code: 404, message: 'Skill file not found or skills are not available' }
          ]
          tags %w[orbit]
        end
        params do
          requires :name, type: String, regexp: /\A[a-z0-9][a-z0-9-]*\z/, desc: 'Deployed skill name'
          requires :path, type: String, regexp: %r{\A[^/]+(?:/[^/]+)*\z}, desc: 'File path relative to the skill root',
            documentation: { example: 'references/usage.md' }
        end
        route_setting :authorization, permissions: :read_orbit, boundary_type: :user
        route_setting :skip_orbit_entitlement, true
        get 'skills/:name/*path', requirements: ::API::NO_FORMAT_SUFFIX_REQUIREMENT do
          require_skills_available!
          check_orbit_query_rate_limit!

          path = params[:path]
          not_found!('Skill file') if path.split('/').intersect?(%w[. ..])

          file = fetch_skill['files'].find { |entry| entry['path'] == path }
          not_found!('Skill file') unless file

          etag = %("#{file['sha256']}")
          header 'ETag', etag
          header 'Cache-Control', SKILL_CACHE_CONTROL
          not_modified! if skill_etag_matches?(etag)

          content_type(path.end_with?('.md') ? 'text/markdown; charset=utf-8' : 'text/plain; charset=utf-8')
          env['api.format'] = :binary
          body(request.head? ? '' : file['content'])
        end
      end
    end
  end
end
