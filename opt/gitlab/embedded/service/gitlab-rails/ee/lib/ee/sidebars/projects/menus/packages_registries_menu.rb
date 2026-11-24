# frozen_string_literal: true

module EE
  module Sidebars
    module Projects
      module Menus
        module PackagesRegistriesMenu
          extend ::Gitlab::Utils::Override

          override :configure_menu_items
          def configure_menu_items
            return false unless super

            add_item(google_artifact_registry_menu_item)

            true
          end

          private

          def google_artifact_registry_menu_item
            unless show_google_artifact_registry_menu_item?
              return ::Sidebars::NilMenuItem.new(item_id: :google_artifact_registry)
            end

            ::Sidebars::MenuItem.new(
              title: _('Google Artifact Registry'),
              link: project_google_cloud_artifact_registry_index_path(context.project),
              super_sidebar_parent: ::Sidebars::Projects::SuperSidebarMenus::DeployMenu,
              active_routes: { controller: 'projects/google_cloud/artifact_registry' },
              item_id: :google_artifact_registry
            )
          end

          def show_google_artifact_registry_menu_item?
            ::Gitlab::Saas.feature_available?(:google_cloud_support) &&
              can?(context.current_user, :read_google_cloud_artifact_registry, context.project) &&
              context.project.google_cloud_platform_workload_identity_federation_integration&.operating? &&
              context.project.google_cloud_platform_artifact_registry_integration&.operating?
          end
        end
      end
    end
  end
end
