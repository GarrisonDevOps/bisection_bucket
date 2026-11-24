# frozen_string_literal: true

module API
  module Entities
    class AiSettings < Grape::Entity
      expose :duo_agent_platform_enabled, documentation: { type: 'Boolean', example: true }
      expose :duo_workflow_mcp_enabled, documentation: { type: 'Boolean', example: false }
      expose :foundational_agents_default_enabled, documentation: { type: 'Boolean', example: true }
      expose :ai_catalog_restricted_to_group_hierarchy, documentation: { type: 'Boolean', example: false }
      expose :ai_usage_data_collection_enabled, documentation: { type: 'Boolean', example: false }
      expose :prompt_injection_protection_level, documentation: { type: 'String', example: 'no_checks' }
      expose :web_search_enabled, documentation: { type: 'Boolean', example: false }
      expose :duo_workflow_file_attachments_enabled, documentation: { type: 'Boolean', example: false },
        if: ->(settings, _) {
          ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) && settings.namespace.root?
        }
      expose :include_recommended_allowed, documentation: { type: 'Boolean', example: false }
      expose :allow_all_unix_sockets, documentation: { type: 'Boolean', example: false }
      expose :allow_project_extension, documentation: { type: 'Boolean', example: true }
      expose :require_sandbox, documentation: { type: 'Boolean', example: false }

      with_options if: ->(_, _) { customizable_permissions_enabled? } do
        expose :minimum_access_level_execute, documentation: { type: 'String', example: 'developer' } do |object|
          ::Gitlab::Access.sym_options_with_admin.key(object.minimum_access_level_execute)&.to_s
        end
        expose :minimum_access_level_execute_async, documentation: { type: 'String', example: 'developer' } do |object|
          ::Gitlab::Access.sym_options_with_admin.key(object.minimum_access_level_execute_async)&.to_s
        end
        expose :minimum_access_level_manage, documentation: { type: 'String', example: 'maintainer' } do |object|
          ::Gitlab::Access.sym_options_with_admin.key(object.minimum_access_level_manage)&.to_s
        end
        expose :minimum_access_level_enable_on_projects,
          documentation: { type: 'String', example: 'maintainer' } do |object|
          ::Gitlab::Access.sym_options_with_admin.key(object.minimum_access_level_enable_on_projects)&.to_s
        end
      end

      private

      def customizable_permissions_enabled?
        ::Feature.enabled?(:dap_group_customizable_permissions, object.namespace&.root_ancestor)
      end
    end
  end
end
