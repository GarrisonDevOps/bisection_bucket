# frozen_string_literal: true

# Gitaly note: JV: no RPC's here.

module Gitlab
  module Git
    class Compare
      attr_reader :head, :base, :straight

      def initialize(repository, base, head, straight: false)
        @repository = repository
        @straight = straight

        unless base && head
          @commits = []
          return
        end

        @base = Gitlab::Git::Commit.find(repository, base.try(:strip))
        @head = Gitlab::Git::Commit.find(repository, head.try(:strip))

        @commits = [] unless @base && @head
        @commits = [] if same
      end

      def same
        @base && @head && @base.id == @head.id
      end

      def commits(limit: nil)
        return @commits if defined?(@commits) && @commits.empty?

        if limit
          return Gitlab::Git::Commit.between(@repository, @base.id, @head.id, limit: limit)
        end

        return @commits if defined?(@commits)

        @commits = Gitlab::Git::Commit.between(@repository, @base.id, @head.id)
      end

      def diffs(options = {})
        unless @head && @base
          return Gitlab::Git::DiffCollection.new([])
        end

        paths = options.delete(:paths) || []
        options[:straight] = @straight
        Gitlab::Git::Diff.between(@repository, @head.id, @base.id, options, *paths)
      end

      # Pass `merge_base` when it is already known, to skip looking it up.
      def generated_files(diffs: nil, merge_base: nil)
        return Set.new unless @base && @head

        diff_base_id = diff_base_id(merge_base)
        changed_paths =
          if diffs
            diffs.map { |diff| Gitlab::Git::ChangedPath.from_diff(diff) }
          else
            @repository.find_changed_paths([Gitlab::Git::DiffTree.new(diff_base_id, @head.id)])
          end

        @repository.detect_generated_files(diff_base_id, @head.id, changed_paths, attributes_revision: @base.id)
      end

      private

      # The commit the diff starts from, as in Gitlab::Git::Diff.between.
      def diff_base_id(merge_base)
        return @base.id if @straight

        merge_base.presence || @repository.merge_base(@head.id, @base.id) || @base.id
      end
    end
  end
end
