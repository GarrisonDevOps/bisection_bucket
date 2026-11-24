# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    module CiAction
      class Base
        attr_reader :action, :ci_variables, :context, :index

        def initialize(action, ci_variables, context, index = 0, opts = {})
          @action = action
          @ci_variables = ci_variables
          @context = context
          @index = index
          @opts = opts
        end

        def config
          raise NotImplementedError
        end

        private

        def generate_job_name_with_index(job_name)
          [job_name.to_s.dasherize, @opts[:job_name_suffix].presence, @index].compact.join('-').to_sym
        end
      end
    end
  end
end
