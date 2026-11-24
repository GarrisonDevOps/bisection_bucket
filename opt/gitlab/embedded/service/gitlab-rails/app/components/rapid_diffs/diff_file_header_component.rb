# frozen_string_literal: true

module RapidDiffs
  class DiffFileHeaderComponent < ViewComponent::Base
    include ButtonHelper
    include DiffHelper
    include Gitlab::Utils::StrongMemoize

    renders_one :before_file_menu

    SYMLINK_MODE = '120000'

    def initialize(diff_file:, additional_menu_items: [], environment: nil)
      @diff_file = diff_file
      @additional_menu_items = additional_menu_items
      @environment = environment
    end

    def file_link
      return if @diff_file.path_traversal?

      helpers.project_blob_path(
        @diff_file.repository.project,
        helpers.tree_join(@diff_file.content_sha, @diff_file.new_path)
      )
    end

    # Title markup for the file heading. Built here so the template can render it
    # inside the "open file" link, or on its own when file_link is dropped for a
    # traversal path.
    def file_title
      path_with_breaks(@diff_file.file_path)
    end

    def renamed_file_title
      old_path = @diff_file.old_path
      new_path = @diff_file.new_path
      old_diffs, new_diffs = Gitlab::Diff::InlineDiff.new(old_path, new_path).inline_diffs

      safe_join([
        Gitlab::Diff::InlineDiffMarker.new(old_path, path_with_breaks(old_path)).mark(old_diffs),
        tag.span('→', class: 'rd-diff-file-moved'),
        Gitlab::Diff::InlineDiffMarker.new(new_path, path_with_breaks(new_path)).mark(new_diffs)
      ])
    end

    def copy_path_button
      clipboard_button(
        text: @diff_file.file_path,
        gfm: "`#{@diff_file.file_path}`",
        title: _("Copy file path"),
        placement: "top",
        boundary: "viewport",
        testid: "rd-diff-file-copy-clipboard",
        class: 'rd-copy-path'
      )
    end

    def menu_items
      [
        view_file_menu_item,
        view_full_file_menu_item,
        view_on_environment_menu_item,
        rich_view_toggle,
        *@additional_menu_items
      ]
                        .compact
                        .sort_by { |item| item[:position] || Float::INFINITY }
    end

    def heading_id
      file_heading_id(@diff_file)
    end

    def root_label
      s_('RapidDiffs|Diff file controls')
    end

    def moved_title_label
      helpers.safe_format(
        s_('RapidDiffs|File moved from %{old} to %{new}'),
        old: @diff_file.old_path,
        new: @diff_file.new_path
      )
    end

    def stats_label
      return false if @diff_file.binary?

      added = @diff_file.added_lines
      removed = @diff_file.removed_lines
      counters = []
      counters << (ns_('RapidDiffs|Added %d line.', 'RapidDiffs|Added %d lines.', added) % added) if added > 0
      counters << (ns_('RapidDiffs|Removed %d line.', 'RapidDiffs|Removed %d lines.', removed) % removed) if removed > 0
      counters.join(' ').presence
    end

    # Gitlab::Diff::File#new_blob/#old_blob can resolve to nil through Blob.lazy
    # when Gitaly does not return a blob.
    def new_blob_size
      @diff_file.new_blob&.size
    end
    strong_memoize_attr :new_blob_size

    def old_blob_size
      @diff_file.old_blob&.size
    end
    strong_memoize_attr :old_blob_size

    def binary_size_delta
      return unless new_blob_size && old_blob_size

      new_blob_size - old_blob_size
    end
    strong_memoize_attr :binary_size_delta

    def pretty_print_bytes(size)
      ActiveSupport::NumberHelper.number_to_human_size(size)
    end

    def view_file_menu_item
      return if @diff_file.path_traversal?

      project = @diff_file.repository.project
      file_path = @diff_file.new_path || @diff_file.old_path
      commit_sha = @diff_file.content_sha

      view_path = helpers.project_blob_path(project, helpers.tree_join(commit_sha, file_path))

      {
        text: s_('RapidDiffs|View file at %{codeStart}%{commit}%{codeEnd}'),
        messageData: {
          commit: @diff_file.content_sha[0..7]
        },
        href: view_path,
        icon: 'document',
        extraAttrs: { target: '_blank' },
        position: 1
      }
    end

    def view_full_file_menu_item
      return if !@diff_file.diffable_text? || expanded? || @diff_file.rendered?

      {
        text: @diff_file.manually_expanded? ? s_('MRDiff|Show changes only') : s_('MRDiff|Show full file'),
        icon: @diff_file.manually_expanded? ? 'doc-changes' : 'doc-expand',
        extraAttrs: { 'data-click': 'showFullFile', 'data-full': @diff_file.manually_expanded? },
        position: 50
      }
    end

    def expanded?
      @diff_file.fully_expanded? && !@diff_file.manually_expanded?
    end

    def view_on_environment_menu_item
      return unless @environment

      file_path = @diff_file.new_path || @diff_file.old_path
      commit_sha = @diff_file.content_sha

      environment_path = @environment.external_url_for(file_path, commit_sha)
      return unless environment_path

      {
        text: helpers.safe_format(
          s_('RapidDiffs|View on %{environment}'),
          environment: @environment.formatted_external_url
        ),
        href: environment_path,
        icon: 'external-link',
        extraAttrs: { target: '_blank', rel: 'noopener noreferrer' },
        position: 2
      }
    end

    def rich_view_toggle
      return unless @diff_file.has_renderable?

      {
        text: @diff_file.rendered? ? s_('RapidDiffs|View plain diff') : s_('RapidDiffs|View rich diff'),
        icon: @diff_file.rendered? ? 'code' : 'doc-text',
        extraAttrs: {
          'data-click': 'toggleRichView',
          'data-rendered': @diff_file.rendered?.to_json
        },
        position: 10
      }
    end

    private

    def status_title_class
      if @diff_file.new_file?
        'rd-diff-file-title-added'
      elsif @diff_file.deleted_file?
        'rd-diff-file-title-removed'
      end
    end

    def status_title_label
      if @diff_file.new_file?
        format(s_('RapidDiffs|New file %{path}'), path: @diff_file.file_path)
      elsif @diff_file.deleted_file?
        format(s_('RapidDiffs|Deleted file %{path}'), path: @diff_file.file_path)
      end
    end

    def symlink?
      (@diff_file.deleted_file? ? @diff_file.a_mode : @diff_file.b_mode) == SYMLINK_MODE
    end

    def mode_change
      Gitlab::Diff::ModeChange.new(@diff_file.a_mode, @diff_file.b_mode)
    end
    strong_memoize_attr :mode_change

    def mode_change_label
      old_mode = mode_change.old_mode
      new_mode = mode_change.new_mode

      if mode_change.type == :other
        format(_('File mode changed from %{from} to %{to}.'), from: old_mode, to: new_mode)
      elsif mode_change.new_file?
        format(s_('RapidDiffs|New executable file: %{mode}'), mode: new_mode)
      elsif mode_change.deleted_file?
        format(s_('RapidDiffs|Deleted executable file: %{mode}'), mode: old_mode)
      elsif mode_change.type == :executable_gained
        format(s_('RapidDiffs|File made executable: %{from} → %{to}'), from: old_mode, to: new_mode)
      else
        format(s_('RapidDiffs|File no longer executable: %{from} → %{to}'), from: old_mode, to: new_mode)
      end
    end

    # allow paths to wrap around '/' symbols for better visuals
    def path_with_breaks(path)
      *dirs, filename = path.split('/')
      safe_join(dirs.flat_map { |dir| [dir, '/', tag.wbr] } + [filename])
    end
  end
end
