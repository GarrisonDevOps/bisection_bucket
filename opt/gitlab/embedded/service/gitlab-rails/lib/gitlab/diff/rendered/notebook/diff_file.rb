# frozen_string_literal: true

module Gitlab
  module Diff
    module Rendered
      module Notebook
        class DiffFile < Gitlab::Diff::File
          include Gitlab::Diff::Rendered::Notebook::DiffFileHelper
          include Gitlab::Utils::StrongMemoize

          RENDERED_TIMEOUT_BACKGROUND = 10.seconds
          BACKGROUND_EXECUTION = 'background'
          FOREGROUND_EXECUTION = 'foreground'
          LOG_IPYNBDIFF_GENERATED = 'IPYNB_DIFF_GENERATED'
          LOG_IPYNBDIFF_TIMEOUT = 'IPYNB_DIFF_TIMEOUT'
          LOG_IPYNBDIFF_INVALID = 'IPYNB_DIFF_INVALID'
          LOG_IPYNBDIFF_TRUNCATED = 'IPYNB_DIFF_TRUNCATED'
          LOG_IPYNBDIFF_FAILED = 'IPYNB_DIFF_FAILED'
          LOG_IPYNBDIFF_OVER_LIMITS = 'IPYNB_DIFF_OVER_LIMITS'
          IPYNB_DIFF_OPTIONS = { raise_if_invalid_nb: true, diffy_opts: { include_diff_info: true } }.freeze
          # About 6x the lines of a 512 KB notebook of ordinary code; one-character-per-line notebooks exceed it.
          RENDERED_LIMITS = { max_lines: 100_000 }.freeze

          attr_reader :source_diff

          delegate :repository, :diff_refs, :fallback_diff_refs, :unfolded, :unique_identifier,
            to: :source_diff

          def initialize(diff_file)
            @source_diff = diff_file
          end

          def old_blob
            return unless notebook_diff

            strong_memoize(:old_blob) { ::Blobs::Notebook.decorate(source_diff.old_blob, notebook_diff.from.as_text) }
          end

          def new_blob
            return unless notebook_diff

            strong_memoize(:new_blob) { ::Blobs::Notebook.decorate(source_diff.new_blob, notebook_diff.to.as_text) }
          end

          def diff
            strong_memoize(:diff) { transformed_diff }
          end

          def has_renderable?
            !notebook_diff.nil? && diff.diff.present?
          end

          def rendered
            notebook_diff ? self : nil
          end

          def rendered?
            true
          end

          def highlighted_diff_lines
            strong_memoize(:highlighted_diff_lines) do
              lines = Gitlab::Diff::Highlight.new(self, repository: self.repository).highlight
              lines_in_source = lines_in_source_diff(
                source_diff.highlighted_diff_lines, source_diff.deleted_file?, source_diff.new_file?
              )

              lines.zip(line_positions_at_source_diff(lines, transformed_blocks))
                   .map { |line, positions| mutate_line(line, positions, lines_in_source) }
            end
          end

          def diff_lines_with_match_tail
            lines = highlighted_diff_lines

            return [] if lines.empty?
            return [] if blob.nil?

            lines
          end
          strong_memoize_attr(:diff_lines_with_match_tail)

          private

          def notebook_diff
            strong_memoize(:notebook_diff) do
              if source_diff.old_blob&.truncated? || source_diff.new_blob&.truncated?
                log_event(LOG_IPYNBDIFF_TRUNCATED)
                next
              end

              project = repository&.project

              if project
                DiffCache.new(project: project, old_blob: source_diff.old_blob, new_blob: source_diff.new_blob)
                  .fetch { render_notebook_diff }
              else
                render_notebook_diff
              end
            rescue Timeout::Error => e
              rendered_timeout.increment(source: Gitlab::Runtime.sidekiq? ? BACKGROUND_EXECUTION : FOREGROUND_EXECUTION)
              log_event(LOG_IPYNBDIFF_TIMEOUT, e)
            rescue IpynbDiff::InvalidNotebookError => e
              log_event(LOG_IPYNBDIFF_INVALID, e)
            rescue IpynbDiff::TransformedNotebookTooLargeError => e
              log_event(LOG_IPYNBDIFF_OVER_LIMITS, e, lines: e.lines, bytes: e.bytes)
            rescue IpynbDiff::DiffError => e
              log_event(LOG_IPYNBDIFF_FAILED, e)
            end
          end

          def render_notebook_diff
            Gitlab::RenderTimeout.timeout(background: RENDERED_TIMEOUT_BACKGROUND) do
              IpynbDiff.diff(source_diff.old_blob&.data, source_diff.new_blob&.data,
                **IPYNB_DIFF_OPTIONS, interruptible: true, limits: RENDERED_LIMITS)&.tap do |notebook_diff|
                # The text diff is lazy: compute it inside the timeout, which kills its process at the limit.
                notebook_diff.diff
                log_event(LOG_IPYNBDIFF_GENERATED)
              end
            end
          end

          def transformed_diff
            return unless notebook_diff

            diff = source_diff.diff.clone
            diff.diff = strip_diff_frontmatter(notebook_diff.to_s(:text))
            diff
          end

          def transformed_blocks
            { from: notebook_diff.from.blocks, to: notebook_diff.to.blocks }
          end

          def rendered_timeout
            @rendered_timeout ||= Gitlab::Metrics.counter(
              :ipynb_semantic_diff_timeouts_total,
              'Counts the times notebook diff rendering timed out'
            )
          end

          def log_event(message, error = nil, **fields)
            Gitlab::AppLogger.info({ message: message, **fields })
            Gitlab::ErrorTracking.log_exception(error) if error
            nil
          end

          def mutate_line(line, mapped_positions, source_diff_lines)
            line.old_pos, line.new_pos = mapped_positions

            # Lines that do not appear on the original diff should not be commentable
            unless source_diff_lines[:to].include?(line.new_pos) || source_diff_lines[:from].include?(line.old_pos)
              line.type = "#{line.type || 'unchanged'}-nomappinginraw"
            end

            line.line_code = line_code(line)

            line.rich_text = image_as_rich_text(line.text) || line.rich_text

            line
          end
        end
      end
    end
  end
end
