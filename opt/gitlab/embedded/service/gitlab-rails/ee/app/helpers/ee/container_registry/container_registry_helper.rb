# frozen_string_literal: true

module EE
  module ContainerRegistry
    module ContainerRegistryHelper
      extend ::Gitlab::Utils::Override

      override :project_container_registry_template_data
      def project_container_registry_template_data(project, connection_error, invalid_path_error)
        super.merge(
          security_configuration_path: project_security_configuration_path(project),
          vulnerability_report_path: project_security_vulnerability_report_index_path(project,
            tab: :CONTAINER_REGISTRY)
        )
      end
    end
  end
end
