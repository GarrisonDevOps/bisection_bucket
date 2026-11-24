# frozen_string_literal: true

require_relative 'fe_test_janitor/directory_walker'
require_relative 'fe_test_janitor/file_analyzer'
require_relative 'fe_test_janitor/reporter'

module Tooling
  # FeTestJanitor walks a directory of *_spec.rb files, runs static signal
  # analysis on each file, and classifies every RSpec example as `migrate`,
  # `reframe`, `partial`, or `keep`.
  #
  # Usage:
  #   Tooling::FeTestJanitor.run("spec/features/work_items/")
  #   Tooling::FeTestJanitor.run("spec/features/work_items/detail/work_item_detail_spec.rb")
  module FeTestJanitor
    def self.run(path, output: $stdout)
      files = DirectoryWalker.new(path).spec_files

      if files.empty?
        output.puts "No *_spec.rb files found under: #{path}"
        return
      end

      file_results = files.map { |f| FileAnalyzer.new(f).analyze }
      Reporter.new.report(file_results, output: output)
    end
  end
end
