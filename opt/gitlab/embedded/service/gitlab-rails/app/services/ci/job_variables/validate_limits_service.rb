# frozen_string_literal: true

module Ci
  module JobVariables
    class ValidateLimitsService
      include Gitlab::Utils::StrongMemoize

      def self.limits_doc_link
        Rails.application.routes.url_helpers.help_page_url(
          'ci/jobs/job_control.md', anchor: 'job-variable-limits'
        )
      end

      def initialize(project, variables)
        @project = project
        @variables = normalize(variables)
      end

      def execute
        # Most job runs supply nothing, and resolving the plan costs a query.
        return ServiceResponse.success if variables.empty?

        message = count_error || size_error
        return ServiceResponse.error(message: message) if message

        ServiceResponse.success
      end

      private

      attr_reader :project, :variables

      # Nested attributes accept a hash keyed by index as well as an array, and
      # the model stores either.
      def normalize(variables)
        return variables.values if variables.respond_to?(:values)

        Array(variables)
      end

      def count_error
        limit = limit_value(:ci_job_variables_count)
        return if limit == 0 || variables.size <= limit

        format(
          _('The number of job variables exceeds the limit of %{limit}. For more information, see %{link}'),
          limit: limit, link: self.class.limits_doc_link
        )
      end

      def size_error
        variable = variables.find { |candidate| oversized?(candidate) }
        return unless variable

        format(
          _('Value for variable %{key} exceeds the %{limit} limit. For more information, see %{link}'),
          # The key is unvalidated here, so bound what the message echoes back.
          key: variable[:key].to_s.truncate(Ci::HasVariable::MAX_KEY_LENGTH),
          limit: ActiveSupport::NumberHelper.number_to_human_size(size_limit_for(variable)),
          link: self.class.limits_doc_link
        )
      end

      def oversized?(variable)
        limit = size_limit_for(variable)
        return false if limit == 0

        variable[:value].to_s.bytesize > limit
      end

      def size_limit_for(variable)
        if variable[:variable_type].to_s == 'file'
          limit_value(:ci_variable_file_value_size)
        else
          limit_value(:ci_variable_value_size)
        end
      end

      def limit_value(name)
        limits[name]
      end

      def limits
        project.actual_limits
      end
      strong_memoize_attr :limits
    end
  end
end
