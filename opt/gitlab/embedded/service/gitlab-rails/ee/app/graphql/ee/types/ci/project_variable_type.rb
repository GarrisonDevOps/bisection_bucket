# frozen_string_literal: true

module EE
  module Types
    module Ci
      module ProjectVariableType
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        override :value
        def value
          record_value_access

          super
        end

        private

        def record_value_access
          scope = variable_scope
          return unless scope

          ::Gitlab::Ci::Variables::AccessCollector
            .for(context)
            .record(scope: scope, key: object.key, hidden: object.hidden?)
        end

        def variable_scope
          object.project
        end
      end
    end
  end
end
