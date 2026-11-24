# frozen_string_literal: true

module Resolvers
  module MergeRequests
    class DiffsResolver < BaseResolver
      include ::Gitlab::Graphql::Authorize::AuthorizeResource

      DEFAULT_PER_PAGE = 20
      MAX_PER_PAGE = 100
      FIRST_PAGE = 1

      authorize :read_merge_request
      authorizes_object!

      calls_gitaly!

      type ::Types::MergeRequests::DiffConnectionType, null: true

      argument :expanded, GraphQL::Types::Boolean,
        required: false,
        default_value: false,
        description: 'Return full patch text even for files that would otherwise be collapsed for size.'

      argument :path, GraphQL::Types::String,
        required: false,
        experiment: { milestone: '19.6' },
        description: 'File path to filter by, matched against the old or new path. ' \
          'Returns all matching files in one page and cannot be combined with `after` or `first`.'

      def self.calculate_ext_conn_complexity
        true
      end

      def self.complexity_multiplier(_args)
        0.05
      end

      def resolve(**args)
        return diffs_for_path(args[:path], args) unless args[:path].nil?

        page = page_from_cursor(args[:after])
        per_page = per_page_from(args[:first])

        collection = object.merge_request_diff.paginated_diffs(page, per_page, { expanded: args[:expanded] })
        git_diffs = collection.diffs
        diffs = git_diffs.to_a

        ::Gitlab::Graphql::MergeRequests::DiffsArray.new(
          previous_cursor(page),
          next_cursor(collection),
          *diffs,
          overflow: git_diffs.overflow?
        )
      end

      private

      # @param path [String]
      # @param args [Hash]
      # @return [Gitlab::Graphql::MergeRequests::DiffsArray]
      def diffs_for_path(path, args)
        raise Gitlab::Graphql::Errors::ArgumentError, 'The path argument must not be blank' if path.blank?

        if args[:after].present?
          raise Gitlab::Graphql::Errors::ArgumentError, 'The path argument cannot be combined with after'
        end

        unless args[:first].nil?
          raise Gitlab::Graphql::Errors::ArgumentError, 'The path argument cannot be combined with first'
        end

        merge_request_diff = object.merge_request_diff
        paths = paths_for(merge_request_diff, path)
        return empty_diffs if paths.nil?

        git_diffs = merge_request_diff.diffs(paths: paths, expanded: args[:expanded]).diffs
        # Repository comparisons use pathspecs; persisted diffs match paths exactly.
        diffs = git_diffs.select { |diff| diff.old_path == path || diff.new_path == path }

        ::Gitlab::Graphql::MergeRequests::DiffsArray.new(
          nil, nil, *diffs, overflow: git_diffs.overflow? || (diffs.empty? && merge_request_diff.overflow?)
        )
      end

      # @param merge_request_diff [MergeRequestDiff]
      # @param path [String]
      # @return [Array<String>, nil]
      def paths_for(merge_request_diff, path)
        return [path] unless merge_request_diff.without_files?

        return [path] if Gitlab::Git.blank_ref?(merge_request_diff.diff_refs&.start_sha)

        match = cleaned_changed_paths(merge_request_diff).find do |entry|
          entry.old_path == path || entry.path == path
        end
        return if match.nil?

        [match.old_path, match.path].compact.uniq
      end

      # @param merge_request_diff [MergeRequestDiff]
      # @return [Array]
      def cleaned_changed_paths(merge_request_diff)
        merge_request_diff.diff_refs&.compare_in(merge_request_diff.project)&.changed_paths || []
      end

      # @return [Gitlab::Graphql::MergeRequests::DiffsArray]
      def empty_diffs
        ::Gitlab::Graphql::MergeRequests::DiffsArray.new(nil, nil, overflow: false)
      end

      def per_page_from(first)
        [first || DEFAULT_PER_PAGE, MAX_PER_PAGE].min
      end

      def page_from_cursor(cursor)
        return FIRST_PAGE if cursor.blank?

        page = Integer(context.schema.cursor_encoder.decode(cursor), exception: false)

        raise Gitlab::Graphql::Errors::ArgumentError, 'Please provide a valid cursor' if page.nil? || page < FIRST_PAGE

        page
      end

      def previous_cursor(page)
        context.schema.cursor_encoder.encode((page - 1).to_s) if page > FIRST_PAGE
      end

      def next_cursor(collection)
        next_page = collection.next_page
        context.schema.cursor_encoder.encode(next_page.to_s) if next_page
      end
    end
  end
end
