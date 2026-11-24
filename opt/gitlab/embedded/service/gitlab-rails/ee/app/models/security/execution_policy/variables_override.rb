# frozen_string_literal: true

module Security
  module ExecutionPolicy
    class VariablesOverride
      DOTENV_ALLOW_OVERRIDE = 'allow_override'

      def initialize(project:, job_options:)
        @project = project
        extract_job_options(job_options)
      end

      # This is the original way of enforcing policy variables.
      # It's used when policies don't specify the `variables_override` option.
      def apply_highest_precedence(variables, yaml_variables)
        return variables unless apply_highest_precedence?

        yaml_variable_keys = yaml_variables.pluck(:key).to_set # rubocop: disable Database/AvoidUsingPluckWithoutLimit -- this is not a DB query
        variables.reject { |var| yaml_variable_keys.include?(var.key) }.concat(yaml_variables)
      end

      def replaces_legacy_scan_execution_policy_variables_builder?
        apply_variables_override? && !pipeline_execution_policy_job?
      end

      # This method applies to both PEP and SEP.
      # SEP defines variables with their values in the policy action that should be enforced
      # and not allowed to be overridden. `variables_override` option is built implicitly for the variables keys.
      # PEP defines `variables_override` explicitly.
      def apply_variables_override(variables, source: nil)
        return variables unless apply_variables_override?
        return variables if source == :dotenv && allow_dotenv_override?

        if override_settings[:allowed]
          override_with_denylist(variables)
        else
          override_with_allowlist(variables)
        end
      end

      private

      attr_reader :project, :override_settings, :policy_job, :pipeline_execution_policy_job

      def extract_job_options(job_options)
        policy_options = job_options&.dig(:policy)
        if policy_options
          @policy_job = true
          @pipeline_execution_policy_job = policy_options[:pipeline_execution_policy_job]
          @override_settings = policy_options[:variables_override]
        else
          # TODO: Remove with https://gitlab.com/gitlab-org/gitlab/-/issues/577272
          @policy_job = @pipeline_execution_policy_job = job_options&.dig(:execution_policy_job)
          @override_settings = job_options&.dig(:execution_policy_variables_override)
        end
      end

      def policy_job?
        !!policy_job
      end

      def pipeline_execution_policy_job?
        !!pipeline_execution_policy_job
      end

      def exceptions
        override_settings[:exceptions] || []
      end

      def apply_highest_precedence?
        pipeline_execution_policy_job? && !apply_variables_override?
      end

      def apply_variables_override?
        policy_job? && !!override_settings
      end

      def allow_dotenv_override?
        # Default to respecting policy rules (secure by default)
        # Customers can opt-out by explicitly setting dotenv: allow_override
        override_settings[:dotenv] == DOTENV_ALLOW_OVERRIDE
      end

      # allowed:true + exceptions: [...]
      def override_with_denylist(variables)
        return variables if exceptions.blank?

        variables.reject { |var| exceptions.include?(var.key) }
      end

      # allowed:false + exceptions: [...]
      def override_with_allowlist(variables)
        exceptions.each_with_object(::Gitlab::Ci::Variables::Collection.new) do |var_key, allowlist|
          allowlist.append(variables[var_key]) if variables[var_key]
        end
      end
    end
  end
end
