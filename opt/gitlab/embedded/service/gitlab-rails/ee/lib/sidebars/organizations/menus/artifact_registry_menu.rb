# frozen_string_literal: true

module Sidebars # rubocop:disable Gitlab/BoundedContexts -- overridden class is not inside a bounded context namespace
  module Organizations
    module Menus
      class ArtifactRegistryMenu < ::Sidebars::Menu
        include ::Gitlab::Utils::StrongMemoize

        override :render?
        def render?
          repositories_path.present? || setup_path.present?
        end

        override :title
        def title
          s_('ArtifactRegistry|Artifact registry')
        end

        override :sprite_icon
        def sprite_icon
          'infrastructure-registry'
        end

        override :pick_into_super_sidebar?
        def pick_into_super_sidebar?
          true
        end

        override :link
        def link
          super || setup_path
        end

        override :active_routes
        def active_routes
          setup_path ? { page: setup_path } : {}
        end

        override :configure_menu_items
        def configure_menu_items
          add_item(repositories_menu_item) if repositories_path

          true
        end

        private

        def gated_in?
          context.current_user.present? &&
            ::ArtifactRegistry::Configuration.configured? &&
            can?(context.current_user, :read_artifact_registry, context.container) &&
            Feature.enabled?(:artifact_registry_ui, context.container)
        end
        strong_memoize_attr :gated_in?

        def repositories_path
          return unless gated_in?

          slug = context.container.artifact_registry_resolved_slug
          return unless slug

          artifact_registry_repositories_organization_path(context.container, slug)
        end
        strong_memoize_attr :repositories_path

        def setup_path
          return unless gated_in?
          return if context.container.artifact_registry_activated?
          return unless can?(context.current_user, :update_organization, context.container)

          artifact_registry_organization_index_path(context.container)
        end
        strong_memoize_attr :setup_path

        def repositories_menu_item
          ::Sidebars::MenuItem.new(
            title: s_('ArtifactRegistry|Repositories'),
            link: repositories_path,
            super_sidebar_parent: ::Sidebars::Organizations::Menus::ArtifactRegistryMenu,
            active_routes: { controller: 'organizations/artifact_registry_repositories' },
            item_id: :artifact_registry_repositories
          )
        end
      end
    end
  end
end
