# frozen_string_literal: true

# Gitaly note: JV: no RPC's here.

module Gitlab
  module Git
    class DiffCollection
      include Enumerable
      include Gitlab::EncodingHelper

      attr_reader :limits

      def self.default_limits
        { max_files: ::Commit.diff_safe_max_files, max_lines: ::Commit.diff_safe_max_lines }
      end

      def self.collect_all_paths?(collect_all_paths)
        Gitlab::Git::Diff.collect_patch_overage? ? collect_all_paths : false
      end

      def self.limits(options = {})
        limits = {}
        defaults = default_limits
        limits[:max_files] = options.fetch(:max_files, defaults[:max_files])
        limits[:max_lines] = options.fetch(:max_lines, defaults[:max_lines])
        limits[:max_bytes] = limits[:max_files] * 5.kilobytes # Average 5 KB per file

        limits[:safe_max_files] = [limits[:max_files], defaults[:max_files]].min
        limits[:safe_max_lines] = [limits[:max_lines], defaults[:max_lines]].min
        limits[:safe_max_bytes] = limits[:safe_max_files] * 5.kilobytes # Average 5 KB per file
        limits[:max_patch_bytes] = Gitlab::Git::Diff.patch_hard_limit_bytes
        limits[:max_patch_bytes_for_file_extension] = options.fetch(:max_patch_bytes_for_file_extension, {})
        limits[:collect_all_paths] = collect_all_paths?(options.fetch(:collect_all_paths, false))
        limits
      end

      def initialize(iterator, options = {})
        @iterator = iterator
        @generated_files = options.fetch(:generated_files, nil)
        @collapse_deleted_files = !!options.fetch(:collapse_deleted_files, false)
        @limits = self.class.limits(options)
        @enforce_limits = !!options.fetch(:limits, true)
        @expanded = !!options.fetch(:expanded, true)
        @offset_index = options.fetch(:offset_index, 0)
        # Set by MergeRequestDiff callers.
        @skip_charset_detection = options.fetch(:skip_charset_detection, false)

        @line_count = 0
        @byte_count = 0
        @overflow = false
        @empty = true
        @array = []
      end

      def each(&block)
        @array.each(&block)

        return if @overflow
        return if @iterator.nil?

        if @iterator.is_a?(Gitlab::GitalyClient::DiffStitcher)
          each_gitaly_patch(&block)
        else
          each_serialized_patch(&block)
        end

        @populated = true

        # Allow iterator to be garbage-collected. It cannot be reused anyway.
        @iterator = nil
      end

      def sort(&block)
        @array = @array.sort(&block)

        self
      end

      def empty?
        any? # Make sure the iterator has been exercised
        @empty
      end

      def overflow?
        populate!
        !!@overflow
      end

      def overflow_max_lines?
        !!@overflow_max_lines
      end

      def overflow_max_bytes?
        !!@overflow_max_bytes
      end

      def overflow_max_files?
        !!@overflow_max_files
      end

      def collapsed_safe_lines?
        !!@collapsed_safe_lines
      end

      def collapsed_safe_files?
        !!@collapsed_safe_files
      end

      def collapsed_safe_bytes?
        !!@collapsed_safe_bytes
      end

      def collapsed_safe_limits?
        !!@collapsed_safe_limits
      end

      def size
        @size ||= count # forces a loop using each method
      end

      def real_size
        populate!

        if @overflow
          "#{size}+"
        else
          size.to_s
        end
      end

      def line_count
        populate!

        @line_count
      end

      def decorate!
        each_with_index do |element, i|
          @array[i] = yield(element)
        end
      end

      alias_method :to_ary, :to_a

      private

      def populate!
        return if @populated

        each {} # force a loop through all diffs
        nil
      end

      def over_safe_limits?(files)
        if files >= limits[:safe_max_files]
          @collapsed_safe_files = true
        elsif @line_count > limits[:safe_max_lines]
          @collapsed_safe_lines = true
        elsif @byte_count >= limits[:safe_max_bytes]
          @collapsed_safe_bytes = true
        end

        @collapsed_safe_files || @collapsed_safe_lines || @collapsed_safe_bytes
      end

      # An explicit `gitlab-generated` marking is a request to collapse, so it
      # takes precedence over auto-expanding a lone file. A caller asking for
      # expansion outright still wins over both.
      def expand_diff?(raw, generated: false, collapse_deleted: false)
        # Deleted files collapse on the same terms as generated ones.
        generated ||= collapse_deleted

        return legacy_expand_diff?(raw, generated: generated) unless @skip_charset_detection

        return true if !@enforce_limits || @expanded
        return false if generated
        return false unless single_file_diff?

        # A single file auto-expands unless it is binary, so only then is the scan worth running.
        !binary_patch?(raw)
      end

      # Scans every patch, even where the result cannot change the answer.
      def legacy_expand_diff?(raw, generated: false)
        # For binary files only check @enforce_limits and @expanded,
        # for non-binary files also auto-expand when it's a single file diff
        allow_expansion = !@enforce_limits || @expanded

        return allow_expansion if binary_patch?(raw)
        return allow_expansion if generated

        single_file_diff? || allow_expansion
      end

      # Submodules have no blobs to show once collapsed, so they are not collapsed.
      def collapse_deleted_file?(raw)
        return false unless @collapse_deleted_files

        if raw.is_a?(Hash)
          !!raw[:deleted_file] && raw[:a_mode] != '160000' && collapsible_deleted_patch?(raw[:diff])
        else
          # A diff Gitaly collapsed is over its limits, and its patch is emptied, so it keeps that reason.
          Gitlab::Git.blank_ref?(raw.to_id) && raw.old_mode != 0o160000 && !raw.try(:collapsed) &&
            collapsible_deleted_patch?(raw.patch)
        end
      end

      # A binary notice or an LFS pointer is a few lines that keep nothing out of the limits,
      # and collapsing it would hide the image preview.
      def collapsible_deleted_patch?(patch)
        !Gitlab::Git::Diff.has_binary_notice?(patch) &&
          !patch.to_s.match?(Gitlab::Diff::File::LFS_POINTER_PATCH_PATTERN)
      end

      # A diff over the safe size limit is already collapsed when built, so it has no lines left to count.
      # One over the hard limit stays as it is: it can't be expanded either.
      def collapsible?(diff)
        diff.line_count > 0 || (diff.collapsed? && !diff.too_large?)
      end

      def collapse_serialized_patch!(diff, deleted:)
        deleted ? diff.collapse_deleted! : diff.collapse!
      end

      def binary_patch?(raw)
        diff_content = raw.is_a?(Hash) ? raw[:diff] : raw.patch

        detect_binary?(diff_content) || Gitlab::Git::Diff.has_binary_notice?(diff_content)
      end

      def single_file_diff?
        # DiffStitcher consumes a stream it cannot count up front, so the stitcher
        # answers this itself; the serialized path iterates an Array.
        return @iterator.single_file? if @iterator.is_a?(Gitlab::GitalyClient::DiffStitcher)

        @iterator.size == 1
      end

      def each_gitaly_patch
        @iterator.each_with_index do |raw, iterator_index|
          @empty = false

          path = raw.to_path
          path = raw.from_path if path.nil? || path.empty?
          generated = @generated_files.include?(path) if @generated_files
          # Diff.new re-encodes raw.patch in place and can leave it as invalid UTF-8, so decide this first.
          collapse_deleted = collapse_deleted_file?(raw)
          expand_diff = expand_diff?(raw, generated: !!generated, collapse_deleted: collapse_deleted)

          options = { expanded: expand_diff }
          options[:generated] = generated unless generated.nil?

          diff = Gitlab::Git::Diff.new(raw, **options)
          diff.collapse_deleted! if collapse_deleted && !expand_diff && collapsible?(diff)

          if raw.collapsed
            @collapsed_safe_limits = true
          end

          if raw.overflow_marker
            @overflow = true
            # If we're requesting patches with `collect_all_paths` enabled, then
            # Once we hit the overflow marker, gitaly has still returned diffs, just without
            # patches, only metadata
            unless @limits[:collect_all_paths]
              break
            end
          end

          if iterator_index >= @offset_index
            @array << diff
            yield diff
          end
        end
      end

      def each_serialized_patch
        i = @array.length

        @iterator.each_with_index do |raw, iterator_index|
          @empty = false

          if @enforce_limits && i >= limits[:max_files]
            @overflow = true
            @overflow_max_files = true
            break
          end

          # Decided before Diff.new, which can re-encode the patch, as in each_gitaly_patch.
          collapse_deleted = collapse_deleted_file?(raw)
          expand_diff = expand_diff?(raw, generated: !!raw[:generated], collapse_deleted: collapse_deleted)
          diff = Gitlab::Git::Diff.new(raw, expanded: expand_diff, skip_charset_detection: @skip_charset_detection)

          # Collapsing before the counters are bumped keeps deleted files out of the line and byte limits.
          if !expand_diff && (over_safe_limits?(i) || collapse_deleted) && collapsible?(diff)
            collapse_serialized_patch!(diff, deleted: collapse_deleted)
          end

          @line_count += diff.line_count
          @byte_count += diff.diff.bytesize

          if @enforce_limits && @line_count >= limits[:max_lines]
            # This last Diff instance pushes us over the lines limit. We stop and
            # discard it.
            @overflow = true
            @overflow_max_lines = true
            break
          end

          if @enforce_limits && @byte_count >= limits[:max_bytes]
            # This last Diff instance pushes us over the lines limit. We stop and
            # discard it.
            @overflow = true
            @overflow_max_bytes = true
            break
          end

          # We should not yield / memoize diffs before the offset index. Though,
          # we still consider the limit buffers for diffs before it.
          if iterator_index >= @offset_index
            yield @array[i] = diff
            i += 1
          end
        end
      end
    end
  end
end
