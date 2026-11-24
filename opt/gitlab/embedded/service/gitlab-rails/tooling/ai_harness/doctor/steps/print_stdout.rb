# frozen_string_literal: true

# rubocop:disable Gitlab/NoCodeCoverageComment -- see perform_doctor_checks/check_ai_references.rb for
# explanation of simplecov:disable on rightward assignment lines (SimpleCov #1033).

module AiHarness
  module Doctor
    module Steps
      class PrintStdout
        # @param context [Hash] the ROP chain context
        # @return [void]
        def self.print(context)
          # simplecov:disable
          context => { stdout_text: String => output }
          # simplecov:enable
          $stdout.print(output) # rubocop:disable Gitlab/DirectStdio -- CLI script, must write to stdout
          nil
        end
      end
    end
  end
end
# rubocop:enable Gitlab/NoCodeCoverageComment
