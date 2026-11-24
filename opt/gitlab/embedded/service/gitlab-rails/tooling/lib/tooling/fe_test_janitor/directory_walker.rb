# frozen_string_literal: true

module Tooling
  module FeTestJanitor
    # Walks a directory (or accepts a single file path) and returns all
    # *_spec.rb file paths found recursively.
    class DirectoryWalker
      def initialize(path)
        @path = path
      end

      # Returns an Array of file paths, sorted (Dir.glob sorts by default).
      def spec_files
        if File.file?(@path)
          raise ArgumentError, "Not a spec file: #{@path}" unless @path.end_with?('_spec.rb')

          [@path]
        elsif File.directory?(@path)
          Dir.glob(File.join(@path, '**', '*_spec.rb'))
        else
          raise ArgumentError, "Path does not exist: #{@path}"
        end
      end
    end
  end
end
