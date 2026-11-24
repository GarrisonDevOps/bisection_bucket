# frozen_string_literal: true

module Security
  module Configuration
    class SetCvsForScannerTypeService
      SCANNER_METHODS = {
        container_scanning: ->(setting, enabled:) { setting.set_cvs_for_container_scanning!(enabled: enabled) },
        dependency_scanning: ->(setting, enabled:) { setting.set_cvs_for_dependency_scanning!(enabled: enabled) }
      }.freeze

      def self.execute(project:, enable:, scanner_type:)
        ServiceResponse.success(
          payload: {
            enabled: SCANNER_METHODS.fetch(scanner_type).call(project.security_setting, enabled: enable)
          }
        )
      rescue ActiveRecord::StatementInvalid => e
        ServiceResponse.error(
          message: e.message,
          payload: { project_id: project.id }
        )
      end
    end
  end
end
