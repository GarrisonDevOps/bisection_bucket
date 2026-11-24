# frozen_string_literal: true

module EE
  module Ci
    module VariablesHelper
      extend ::Gitlab::Utils::Override

      override :ci_variables_secrets_manager_cta_in_variables_data
      def ci_variables_secrets_manager_cta_in_variables_data(entity)
        data = secrets_manager_variables_cta_data(entity)
        return super if data.blank?

        data.to_json
      end
    end
  end
end
