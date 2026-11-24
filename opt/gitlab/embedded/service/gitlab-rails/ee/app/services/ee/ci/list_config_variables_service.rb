# frozen_string_literal: true

module EE
  module Ci
    module ListConfigVariablesService
      extend ::Gitlab::Utils::Override

      private

      override :additional_variables
      def additional_variables(sha, ref)
        return {} unless sha

        ::Security::PipelineExecutionPolicies::PrefillVariablesService
          .new(project: project, current_user: current_user, sha: sha, ref: ref).execute
      end
    end
  end
end
