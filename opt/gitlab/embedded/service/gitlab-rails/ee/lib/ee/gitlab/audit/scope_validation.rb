# frozen_string_literal: true

module EE
  module Gitlab
    module Audit
      module ScopeValidation
        extend ::Gitlab::Utils::Override

        private

        override :permitted_scope_classes
        def permitted_scope_classes
          super + ['Gitlab::Audit::InstanceScope']
        end
      end
    end
  end
end
