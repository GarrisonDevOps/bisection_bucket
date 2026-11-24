# frozen_string_literal: true

module Vulnerabilities
  module ConsistencyChecks
    class HasVulnerabilitiesIsCorrectCheck < BaseCheck
      synchronous_check!

      def consistent?
        project.project_setting.has_vulnerabilities? == actually_has_vulnerabilities
      end

      def fix!
        project.project_setting.update!(has_vulnerabilities: actually_has_vulnerabilities)

        log('Fixed incorrect has_vulnerabilities value')
      end

      private

      def actually_has_vulnerabilities
        project.vulnerabilities.exists?
      end
      strong_memoize_attr :actually_has_vulnerabilities
    end
  end
end
