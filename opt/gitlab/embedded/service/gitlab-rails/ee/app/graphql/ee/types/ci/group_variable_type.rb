# frozen_string_literal: true

module EE
  module Types
    module Ci
      module GroupVariableType
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        private

        # GroupVariableType inherits from ProjectVariableType, so without this
        # override a group variable would resolve its owner as a project.
        override :variable_scope
        def variable_scope
          object.group
        end
      end
    end
  end
end
