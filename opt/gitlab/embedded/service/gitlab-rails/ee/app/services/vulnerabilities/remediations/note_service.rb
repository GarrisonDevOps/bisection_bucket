# frozen_string_literal: true

module Vulnerabilities
  module Remediations
    class NoteService
      include Gitlab::Utils::StrongMemoize

      def initialize(vulnerable_mr, resolution_mr, vulnerability, user)
        raise_argument_error if nil_params?(vulnerable_mr, resolution_mr, vulnerability, user)

        @vulnerable_mr = vulnerable_mr
        @project = vulnerable_mr.project
        @user = user
        # rubocop:disable CodeReuse/Presenter -- Presenter methods are used in ERB presentation.
        @finding_presenter = Vulnerabilities::FindingPresenter.new(vulnerability.finding)
        # rubocop:enable CodeReuse/Presenter
        @resolution_mr_url = Gitlab::Routing.url_helpers.project_merge_request_url(
          project,
          resolution_mr
        )
      end

      def execute
        note = Notes::CreateService.new(project, user, attrs.compact).execute

        note.valid? ? note : nil
      end

      private

      attr_reader :vulnerable_mr, :resolution_mr_url, :user, :project, :finding_presenter

      def raise_argument_error
        raise ArgumentError, 'All params required to be non-nil'
      end

      def nil_params?(*params)
        params.any?(&:nil?)
      end

      def note_text
        msg = _('Vulnerability Resolution has generated a fix in an MR for this vulnerability.' \
          '%{line_break}%{line_break}In order to apply the fix, merge the following MR:' \
          '%{line_break}%{resolution_mr_url}')
        format(msg, resolution_mr_url: "#{resolution_mr_url}+s", line_break: '<br/>')
      end

      def attrs
        attrs = {
          position: {
            position_type: "text",
            new_path: file,
            base_sha: vulnerable_mr.latest_merge_request_diff&.base_commit_sha,
            head_sha: vulnerable_mr.latest_merge_request_diff&.head_commit_sha,
            start_sha: vulnerable_mr.latest_merge_request_diff&.start_commit_sha,
            ignore_whitespace_change: false,
            new_line: start_line
          },
          note: note_text,
          type: "DiffNote",
          noteable_type: 'MergeRequest',
          noteable_id: vulnerable_mr.id
        }

        # look for a line in the diff where the new line number
        # matches the finding line number. If we find this, we
        # will attach the note at the line we found
        vulnerable_mr.raw_diffs(limits: true, paths: [file]).each do |diff|
          next unless diff.new_path == file

          lines = Gitlab::Diff::Parser.new.parse(diff.diff.each_line)
          line = lines.find { |line| line.new_pos == start_line }

          attrs[:line_code] = Gitlab::Git.diff_line_code(diff.new_path, line.new_pos, line.old_pos) if line
        end

        # It is possible the finding was detected in the file, but
        # the line it was detected on is an unchanged line and is
        # not in the diff.
        #
        # In this case, we change the note to be a general
        # discussion note and it isn't attached to a specific
        # line.
        if attrs[:line_code].nil?
          attrs[:type] = "DiscussionNote"
          attrs[:position] = nil
        end

        attrs
      end

      def file
        finding_presenter.file
      end
      strong_memoize_attr :file

      def start_line
        finding_presenter.location[:start_line]
      end
      strong_memoize_attr :start_line
    end
  end
end
