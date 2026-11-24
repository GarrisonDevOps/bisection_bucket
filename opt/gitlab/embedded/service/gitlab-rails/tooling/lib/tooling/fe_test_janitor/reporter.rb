# frozen_string_literal: true

module Tooling
  module FeTestJanitor
    # Formats and prints analysis results to an IO stream (default: $stdout).
    class Reporter
      VERDICT_WIDTH = 7 # length of longest label ("migrate")

      # Accepts an Array of FileAnalyzer::FileResult objects. Returns the output stream.
      def report(file_results, output: $stdout)
        totals = { migrate: 0, reframe: 0, partial: 0, keep: 0, shared: 0 }

        file_results.each do |file_result|
          print_file_header(file_result.path, output: output)

          if file_result.example_results.empty?
            output.puts "  (no examples found)"
            next
          end

          file_result.example_results.each do |er|
            verdict = er.classification.verdict
            totals[verdict] += 1
            print_example(er, output: output)
          end

          output.puts
        end

        print_summary(file_results.size, totals, output: output)

        output
      end

      private

      def print_file_header(path, output:)
        output.puts "FILE: #{path}"
      end

      def print_example(example_result, output:)
        example     = example_result.example
        verdict     = example_result.classification.verdict
        reasons     = example_result.classification.reasons
        label       = verdict.to_s.ljust(VERDICT_WIDTH)
        reason_text = reasons.empty? ? "no signals detected (defaulting to keep)" : reasons.join("; ")

        output.puts "  [#{label}] #{truncate(example.description, 70)} (line #{example.line_number})"
        output.puts "    Reason: #{reason_text}"
      end

      def print_summary(file_count, totals, output:)
        total_examples = totals.values.sum - totals[:shared]
        output.puts "=== Summary ==="
        output.puts "Files scanned : #{file_count}"
        output.puts "Examples found: #{total_examples}"
        output.puts "  migrate     : #{totals[:migrate]}"
        output.puts "  reframe     : #{totals[:reframe]}"
        output.puts "  partial     : #{totals[:partial]}"
        output.puts "  keep        : #{totals[:keep]}"
        output.puts "Shared example calls (not analyzed): #{totals[:shared]}"
      end

      def truncate(str, max)
        str.length > max ? "#{str[0, max - 3]}..." : str
      end
    end
  end
end
