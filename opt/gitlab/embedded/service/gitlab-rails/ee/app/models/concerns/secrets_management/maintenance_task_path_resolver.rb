# frozen_string_literal: true

module SecretsManagement
  # Shared path helpers for SecretsManager maintenance task models. The
  # maintenance task is the source-of-truth for OpenBao paths during async
  # deprovision: cleanup must keep working even when the secrets manager
  # record (and its parent) are gone, so paths are computed from the task's
  # own stored IDs.
  #
  # Including models must define `secrets_manager_class` (returning the
  # ProjectSecretsManager or GroupSecretsManager class). Builders shared by
  # both SM models (`build_org_path`, `build_root_namespace_path`) live in
  # `SecretsManagers::PathBuilder` and are inherited via the SM class.
  module MaintenanceTaskPathResolver
    extend ActiveSupport::Concern

    def org_path
      secrets_manager_class.build_org_path(organization_id)
    end

    def root_namespace_path
      secrets_manager_class.build_root_namespace_path(root_namespace_id)
    end

    class_methods do
      # Each task class must declare which SecretsManager class supplies the
      # entity-level builder (e.g. build_project_path / build_group_path).
      def secrets_manager_class(klass = nil)
        if klass
          @secrets_manager_class = klass
        else
          @secrets_manager_class
        end
      end
    end

    private

    def secrets_manager_class
      self.class.secrets_manager_class
    end
  end
end
