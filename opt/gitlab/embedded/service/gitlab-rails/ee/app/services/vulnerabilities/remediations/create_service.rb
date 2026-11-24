# frozen_string_literal: true

module Vulnerabilities
  module Remediations
    class CreateService
      include BaseServiceUtility
      include ::Gitlab::Utils::StrongMemoize

      def initialize(project:, diff:, findings:, summary:)
        @project = project
        @diff = diff
        @findings = findings
        @summary = summary || "Vulnerability Remediation"
      end

      def execute
        return error_response("No findings given to relate remediation to") unless @findings.present?

        # rubocop:disable CodeReuse/ActiveRecord -- There is no value in abstracting this
        remediation = Vulnerabilities::Remediation.find_or_create_by(project:, checksum:) do |remediation|
          # rubocop:enable CodeReuse/ActiveRecord
          remediation.file = Tempfile.new.tap { |f| f.write(@diff) }
          remediation.summary = @summary
          remediation.findings = @findings
        end

        # Resetting the `remediations` association for the findings is important because while creating the `finding`
        # record, the validation on the `solution` attributes already loads the remediations into memory.
        # As the association between the `findings` and `remediations` is "Has Many Though", later setting the findings
        # of remediations while creating them does not automatically set the remediations of findings.
        # This is a limitation of the "Has Many Through" association.
        # Therefore, we need to clear the association cache to hit the database again when remediations are needed.
        @findings.each { |finding| finding.association(:remediations).reset }

        remediation.save ? success_response(remediation) : error_response("Remediation creation failed")
      end

      private

      attr_reader :project

      def checksum
        Digest::SHA256.hexdigest(@diff)
      end

      def error_response(message)
        ServiceResponse.error(message: message)
      end

      def success_response(remediation)
        ServiceResponse.success(payload: { remediation: remediation })
      end
    end
  end
end
