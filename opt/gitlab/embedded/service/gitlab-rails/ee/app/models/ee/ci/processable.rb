# frozen_string_literal: true

module EE
  module Ci
    module Processable
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      prepended do
        scope :with_build_source, ->(source) {
          joins(:job_source).where(p_ci_build_sources: { source: source })
        }
      end

      override :dependency_variables
      def dependency_variables
        ::Security::ExecutionPolicy::VariablesOverride
          .new(project: project, job_options: options)
          .apply_variables_override(super, source: :dotenv)
      end

      override :retryable?
      def retryable?
        return false if pipeline.completed_merge_train_pipeline?

        super
      end
    end
  end
end
