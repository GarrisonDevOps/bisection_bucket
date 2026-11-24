# frozen_string_literal: true

module SecretsManagement
  module SecretsManagers
    # Shared path-builder class methods for ProjectSecretsManager and
    # GroupSecretsManager. The two levels that are common across both scopes
    # live here; entity-level builders (`build_project_path`,
    # `build_group_path`, and the full-path joiners) stay on each model since
    # they take scope-specific IDs.
    module PathBuilder
      extend ActiveSupport::Concern

      class_methods do
        def build_org_path(organization_id)
          "org_#{organization_id}"
        end

        def build_root_namespace_path(root_namespace_id)
          "group_#{root_namespace_id}"
        end
      end
    end
  end
end
