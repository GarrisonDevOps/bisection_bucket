# frozen_string_literal: true

module EE
  module API
    module Helpers
      module VariablesHelpers
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        prepended do
          params :optional_group_variable_params_ee do
            optional :environment_scope, type: String, desc: 'The environment scope of the variable'
          end
        end

        override :filter_variable_parameters
        def filter_variable_parameters(owner, params)
          if owner.is_a?(::Group) && !owner.scoped_variables_available?
            params.delete(:environment_scope)
          end

          params
        end

        override :audit_single_variable_access
        def audit_single_variable_access(variable, scope)
          message = "CI/CD variable '#{variable.key}' accessed with the API"
          message += " (hidden variable, no value shown)" if variable.hidden?

          audit_context = {
            name: 'variable_viewed_api',
            author: current_user,
            scope: scope,
            target: variable,
            message: message
          }
          ::Gitlab::Audit::Auditor.audit(audit_context)
        end

        override :audit_all_variables_access
        def audit_all_variables_access(scope)
          message = "CI/CD variables accessed with the API"

          audit_context = {
            name: 'variable_viewed_api',
            author: current_user,
            scope: scope,
            target: scope,
            message: message
          }
          ::Gitlab::Audit::Auditor.audit(audit_context)
        end
      end
    end
  end
end
