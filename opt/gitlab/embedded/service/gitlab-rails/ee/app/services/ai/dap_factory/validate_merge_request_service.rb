# frozen_string_literal: true

module Ai
  module DapFactory
    # Reports what Sync will do with the `.gitlab-dap-factory.yml` of a merge request, in one note that is
    # updated on every push. Nothing is applied until the file is on the default branch.
    class ValidateMergeRequestService
      include ::Gitlab::Utils::StrongMemoize

      MARKER = '<!-- dap-factory:validation -->'
      MARKDOWN_SPECIAL = /[\\`*_{}\[\]()#+!|<>@~&$:%^.]/

      def initialize(merge_request:)
        @merge_request = merge_request
      end

      def execute
        return ServiceResponse.success(payload: { skipped: true }) unless merge_request.opened?

        note = existing_note

        unless applicable?
          note&.destroy!
          return ServiceResponse.success(payload: { skipped: true })
        end

        body = note_body

        # Written directly rather than through Notes::CreateService on purpose: a status note from the bot
        # should not notify participants or create to-dos on every push.
        if note
          note.update!(note: body) unless note.note == body
        else
          merge_request.notes.create!(project: merge_request.project, author: author, note: body)
        end

        ServiceResponse.success
      end

      private

      attr_reader :merge_request

      def applicable?
        merge_request.source_project.present? &&
          merge_request.source_branch_sha.present? &&
          merge_request.target_branch == merge_request.target_project.default_branch &&
          merge_request.modified_paths.include?(path)
      end

      def path
        ::Gitlab::Ai::DapFactory::Configuration::PATH
      end

      def author
        ::Users::Internal.in_organization(merge_request.project.organization).automation_bot
      end
      strong_memoize_attr :author

      def existing_note
        merge_request.notes.authored_by(author).note_starting_with(MARKER).first
      end

      def note_body
        content = merge_request.source_project.repository
          .blob_at(merge_request.source_branch_sha, path, limit: SyncService::READ_LIMIT)&.data
        return removed_body if content.nil?

        result = ::Gitlab::Ai::DapFactory::Validator.new(content: content, project: project_for_checks).execute
        body = result.valid? ? valid_body(result) : invalid_body(result)
        return body if project_for_checks

        [body, s_('DapSoftwareFactory|Statuses and flows were not checked against the project, because the ' \
          'author of this merge request cannot manage its flow triggers. Sync checks them when the file is ' \
          'merged.')].join("\n\n")
      end

      # Project checks run only for an author who could sync the target themselves; otherwise the note would
      # tell a fork author which flows the target project has enabled.
      def project_for_checks
        target = merge_request.target_project
        allowed = SyncService::TRIGGER_PERMISSIONS.all? do |permission|
          Ability.allowed?(merge_request.author, permission, target)
        end

        target if allowed
      end
      strong_memoize_attr :project_for_checks

      def removed_body
        [
          MARKER,
          format(s_('DapSoftwareFactory|**DAP Software Factory:** this merge request removes `%{path}`. ' \
            'When it is merged into `%{branch}`, Sync deletes every trigger it created, provided whoever ' \
            'merges it can manage flow triggers.'),
            path: path, branch: target_branch)
        ].join("\n\n")
      end

      def valid_body(result)
        lines = [
          MARKER,
          format(s_('DapSoftwareFactory|**DAP Software Factory:** `%{path}` is valid. ' \
            'When this merge request is merged into `%{branch}`, Sync applies it, provided whoever ' \
            'merges it can manage flow triggers.'),
            path: path, branch: target_branch)
        ]
        lines << message_list(s_('DapSoftwareFactory|Warnings:'), result.warnings) if result.warnings.any?
        lines.join("\n\n")
      end

      def invalid_body(result)
        lines = [
          MARKER,
          format(
            ns_('DapSoftwareFactory|**DAP Software Factory:** `%{path}` has %{count} problem. ' \
              'Sync does not apply the file, and changes no triggers, until it is fixed.',
              'DapSoftwareFactory|**DAP Software Factory:** `%{path}` has %{count} problems. Sync does not apply the ' \
                'file, and changes no triggers, until they are fixed.',
              result.errors.size),
            path: path, count: result.errors.size
          ),
          message_list(nil, result.errors)
        ]
        lines << message_list(s_('DapSoftwareFactory|Warnings:'), result.warnings) if result.warnings.any?
        lines.join("\n\n")
      end

      def message_list(heading, messages)
        items = messages.map do |message|
          text = escape_markdown(message.message)
          message.path ? "- `#{message.path.gsub(%r{[^\w./-]}, '')}`: #{text}" : "- #{text}"
        end

        [heading, items.join("\n")].compact.join("\n\n")
      end

      # Messages quote keys and values from the file, and the note is posted as a bot, so file content must
      # not be able to add links, images, mentions, or new lines and list items.
      def escape_markdown(text)
        text.squish.gsub(MARKDOWN_SPECIAL) { |char| "\\#{char}" }
      end

      def target_branch
        merge_request.target_branch
      end
    end
  end
end
