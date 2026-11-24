# frozen_string_literal: true

module API
  module Admin
    class KnowledgeGraph < ::API::Base
      MAX_RESULTS = 20

      feature_category :knowledge_graph
      urgency :low

      helpers do
        def ensure_orbit_licensed!
          forbidden! unless ::License.feature_available?(:orbit)
        end

        def ensure_root_namespace!(namespace)
          return if namespace.root?

          error!('Namespace must be a root namespace', 400)
        end

        def render_turn_on_error!(result)
          case result.reason
          when :forbidden, :trial_required, :purchase_required, :trial_ended then forbidden!(result.message)
          when :unavailable then service_unavailable!(result.message)
          else bad_request!(result.message)
          end
        end
      end

      before do
        authenticated_as_admin!
        ensure_orbit_licensed!
      end

      namespace 'admin' do
        resources 'knowledge_graph/namespaces' do
          desc 'Get all enabled namespaces for Knowledge Graph' do
            detail 'This endpoint retrieves all namespaces that have Knowledge Graph enabled'
            success Entities::Analytics::KnowledgeGraph::EnabledNamespace
            is_array true
            failure [
              { code: 400, message: '400 Bad Request' },
              { code: 401, message: '401 Unauthorized' },
              { code: 403, message: '403 Forbidden' }
            ]
            tags ['knowledge_graph']
          end
          route_setting :tier, :premium
          route_setting :authorization,
            permissions: :read_knowledge_graph_enabled_namespace, boundary_type: :instance,
            assignable_when: [:admin]
          get do
            enabled_namespaces = ::Analytics::KnowledgeGraph::EnabledNamespace.recent.with_limit(MAX_RESULTS)

            present enabled_namespaces, with: Entities::Analytics::KnowledgeGraph::EnabledNamespace
          end

          desc 'Enable a namespace for Knowledge Graph' do
            detail 'This endpoint enables Knowledge Graph for a specific namespace'
            success Entities::Analytics::KnowledgeGraph::EnabledNamespace
            failure [
              { code: 400, message: '400 Bad Request' },
              { code: 401, message: '401 Unauthorized' },
              { code: 403, message: '403 Forbidden' },
              { code: 404, message: '404 Not found' },
              { code: 503, message: '503 Service Unavailable' }
            ]
            tags ['knowledge_graph']
          end
          params do
            requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the namespace.'
          end
          route_setting :tier, :premium
          route_setting :authorization,
            permissions: :create_knowledge_graph_enabled_namespace, boundary_type: :instance,
            assignable_when: [:admin]
          put ':id' do
            namespace = find_namespace!(params[:id])
            ensure_root_namespace!(namespace)

            result = ::Analytics::KnowledgeGraph::ToggleNamespaceService
              .new(group: namespace, current_user: current_user, enabled: true)
              .execute
            render_turn_on_error!(result) if result.error?

            present namespace.knowledge_graph_enabled_namespace,
              with: Entities::Analytics::KnowledgeGraph::EnabledNamespace
          end

          desc 'Disable a namespace for Knowledge Graph' do
            detail 'This endpoint disables Knowledge Graph for a specific namespace'
            success code: 204
            failure [
              { code: 400, message: '400 Bad Request' },
              { code: 401, message: '401 Unauthorized' },
              { code: 403, message: '403 Forbidden' },
              { code: 404, message: '404 Not found' }
            ]
            tags ['knowledge_graph']
          end
          params do
            requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the namespace.'
          end
          route_setting :tier, :premium
          route_setting :authorization,
            permissions: :delete_knowledge_graph_enabled_namespace, boundary_type: :instance,
            assignable_when: [:admin]
          delete ':id' do
            namespace = find_namespace!(params[:id])
            ensure_root_namespace!(namespace)

            enabled_namespace = ::Analytics::KnowledgeGraph::EnabledNamespace
              .for_root_namespace_id(namespace.id)
              .first

            not_found!('Analytics::KnowledgeGraph::EnabledNamespace') unless enabled_namespace

            enabled_namespace.destroy!

            no_content!
          end
        end
      end
    end
  end
end
