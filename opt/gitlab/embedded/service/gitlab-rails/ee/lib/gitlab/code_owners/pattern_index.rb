# frozen_string_literal: true

module Gitlab
  module CodeOwners
    class PatternIndex
      # `FNM_DOTMATCH` makes sure we also match files starting with a `.`
      # `FNM_PATHNAME` makes sure ** matches path separators
      FNMATCH_FLAGS = (::File::FNM_DOTMATCH | ::File::FNM_PATHNAME).freeze

      # @param parsed_data [Hash{String => Hash{String => Entry}}]
      #   Section-keyed hash of pattern => Entry, as produced by CodeOwners::File#parsed_data.
      def initialize(parsed_data)
        @parsed_data = parsed_data
        @section_indices = build_section_indices
      end

      # Returns matching entries for a file path, preserving the same
      # semantics as the brute-force matcher:
      # - one entry per section (last matching non-exclusion wins)
      # - any matching exclusion suppresses that section entirely
      #
      # @param path [String] file path, with or without a leading slash
      # @return [Array<Entry>] matched entries duplicated from parsed_data
      def entries_for_path(path)
        path = "/#{path}" unless path.start_with?('/')
        segments = path.delete_prefix('/').split('/')

        matches = []

        @parsed_data.each do |section_name, section_entries|
          idx = @section_indices[section_name]
          candidates = collect_candidates(idx[:root], segments)
          candidates.concat(idx[:fallbacks])

          next if candidates.empty?

          best_entry = nil
          has_exclusion = false

          candidates.each do |pattern|
            next unless path_matches?(pattern, path)

            entry = section_entries[pattern]

            if entry.exclusion?
              has_exclusion = true
              break
            elsif best_entry.nil? || entry.line_number > best_entry.line_number
              best_entry = entry
            end
          end

          next if has_exclusion
          next unless best_entry

          matches << best_entry.dup
        end

        matches
      end

      private

      def build_section_indices
        indices = {}

        @parsed_data.each do |section_name, section_entries|
          root = new_node
          fallbacks = []

          section_entries.each_key do |pattern|
            prefix = static_prefix(pattern)

            if prefix.nil?
              fallbacks << pattern
            elsif prefix.end_with?('/')
              segments = prefix.delete_prefix('/').chomp('/').split('/')
              node = descend_or_create(root, segments)
              node[:patterns] << pattern
            else
              segments = prefix.delete_prefix('/').split('/')
              filename = segments.pop
              node = descend_or_create(root, segments)
              (node[:exact_files][filename] ||= []) << pattern
            end
          end

          indices[section_name] = {
            root: root,
            fallbacks: fallbacks.freeze
          }
        end

        indices
      end

      # Extracts the longest static directory or file prefix from a normalized
      # pattern. Returns nil if glob characters appear before the prefix becomes
      # useful for trie indexing, for example "/**/*.rb".
      #
      # @param pattern [String] normalized CODEOWNERS pattern
      # @return [String, nil]
      def static_prefix(pattern)
        glob_idx = pattern.index(/[*?\[]/)
        prefix = glob_idx.nil? ? pattern : pattern[0...glob_idx]

        return if prefix.include?('\\')
        return pattern if glob_idx.nil?

        return if prefix.length <= 1

        last_slash = prefix.rindex('/')
        return unless last_slash && last_slash > 0

        prefix[0..last_slash]
      end

      # Walks the trie from the root along the path segments, collecting
      # candidate pattern keys from each ancestor directory and any exact-file
      # entries at the leaf.
      #
      # @param root [Hash] trie root node
      # @param segments [Array<String>] path segments without the leading slash
      # @return [Array<String>] candidate pattern keys to verify with fnmatch
      def collect_candidates(root, segments)
        candidates = []
        node = root

        candidates.concat(node[:patterns])

        segments.each_with_index do |segment, i|
          candidates.concat(node[:exact_files][segment]) if i == segments.size - 1 && node[:exact_files].key?(segment)

          child = node[:children][segment]
          break unless child

          node = child
          candidates.concat(node[:patterns])
        end

        candidates
      end

      def new_node
        { children: {}, patterns: [], exact_files: {} }
      end

      def descend_or_create(node, segments)
        segments.each do |seg|
          node[:children][seg] ||= new_node
          node = node[:children][seg]
        end

        node
      end

      def path_matches?(pattern, path)
        ::File.fnmatch?(pattern, path, FNMATCH_FLAGS)
      end
    end
  end
end
