# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Concerns
        module JobLoggable
          include ::Gitlab::Utils::StrongMemoize

          JOB_LAST_LINES_AMOUNT = 1000

          def job_log
            # Line limit should be reworked based on
            # the results of the prompt library and prompt engineering.
            # 1000*100/4
            # 1000 lines, ~100 char per line (can be more), ~4 tokens per character
            # ~25000 tokens
            job.trace.raw(last_lines: JOB_LAST_LINES_AMOUNT)
          end

          strong_memoize_attr :job_log
        end
      end
    end
  end
end
