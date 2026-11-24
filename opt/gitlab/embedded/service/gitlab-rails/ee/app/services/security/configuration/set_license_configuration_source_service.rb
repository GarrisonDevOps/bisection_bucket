# frozen_string_literal: true

module Security
  module Configuration
    class SetLicenseConfigurationSourceService
      attr_reader :project

      def self.execute(project:, source:)
        new(project).execute(source)
      end

      def initialize(project)
        @project = project
      end

      def execute(source)
        ServiceResponse.success(
          payload: {
            license_configuration_source: update_license_configuration_source!(source),
            errors: []
          })
      rescue StandardError => e
        ServiceResponse.error(
          message: e.message,
          payload: { license_configuration_source: nil }
        )
      end

      private

      def update_license_configuration_source!(source)
        unless project.security_setting
          raise ActiveRecord::RecordNotFound,
            "Security setting does not exist for this project."
        end

        source if project.security_setting.update!(license_configuration_source: source)
      end
    end
  end
end
