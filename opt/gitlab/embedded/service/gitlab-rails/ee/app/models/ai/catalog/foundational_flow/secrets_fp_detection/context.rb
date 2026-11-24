# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module SecretsFpDetection
        module Context
          module_function

          def call(runtime_context:)
            resource = runtime_context.resource
            return {} unless resource.is_a?(::Vulnerability)

            finding = resource.finding
            return {} if finding.nil? || finding.secret_redacted?

            raw_value = finding.token_value
            return {} if raw_value.blank?

            { "secret_value" => raw_value }
          end
        end
      end
    end
  end
end
