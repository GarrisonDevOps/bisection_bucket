# frozen_string_literal: true

module EE
  module TodosFinder
    extend ActiveSupport::Concern

    EE_TODO_TYPES = (::TodosFinder::TODO_TYPES + %w[Epic Vulnerability User
      ComplianceManagement::Projects::ComplianceViolation Ai::DuoWorkflows::Workflow]).freeze

    class_methods do
      extend ::Gitlab::Utils::Override

      override :todo_types
      def todo_types
        EE_TODO_TYPES
      end
    end
  end
end
