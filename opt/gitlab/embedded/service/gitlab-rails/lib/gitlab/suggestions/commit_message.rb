# frozen_string_literal: true

module Gitlab
  module Suggestions
    class CommitMessage
      DEFAULT_SUGGESTION_COMMIT_MESSAGE =
        "Apply %{suggestions_count} suggestion(s) to %{files_count} file(s)\n\n%{co_authored_by}"

      def initialize(user, suggestion_set, custom_message = nil)
        @user = user
        @suggestion_set = suggestion_set
        @custom_message = custom_message
      end

      def message
        project = suggestion_set.target_project
        user_defined_message = @custom_message.presence || project.suggestion_commit_message.presence
        message = user_defined_message || DEFAULT_SUGGESTION_COMMIT_MESSAGE
        context_values = self.class.context_values(user, project, suggestion_set.branch)

        Gitlab::StringPlaceholderReplacer
          .replace_string_placeholders(message, PLACEHOLDERS_REGEX) do |key|
          context_values.fetch(key) { PLACEHOLDERS[key].call(user, suggestion_set) }
        end
      end

      # Values that don't depend on the suggestions being applied, so the UI can preview them.
      def self.context_values(user, project, branch)
        CONTEXT_PLACEHOLDERS.transform_values { |value| value.call(user, project, branch) }
      end

      def self.format_paths(paths)
        paths.sort.join(', ')
      end

      private_class_method :format_paths

      private

      attr_reader :user, :suggestion_set

      CONTEXT_PLACEHOLDERS = {
        'branch_name' => ->(user, project, branch) { branch },
        'project_name' => ->(user, project, branch) { project.name },
        'project_path' => ->(user, project, branch) { project.path },
        'user_full_name' => ->(user, project, branch) { user&.name },
        'username' => ->(user, project, branch) { user&.username }
      }.freeze

      PLACEHOLDERS = {
        'files_count' => ->(user, suggestion_set) { suggestion_set.file_paths.length },
        'file_paths' => ->(user, suggestion_set) { format_paths(suggestion_set.file_paths) },
        'suggestions_count' => ->(user, suggestion_set) { suggestion_set.suggestions.size },
        'co_authored_by' => ->(user, suggestions_set) {
          suggestions_set.authors.without(user).map do |author|
            "#{Commit::CO_AUTHORED_TRAILER}: #{author.name} <#{author.commit_email_or_default}>"
          end.join("\n")
        }
      }.freeze

      # This regex is built dynamically using the keys from the PLACEHOLDER struct.
      # So, we can easily add new placeholder just by modifying the PLACEHOLDER hash.
      # This regex will build the new PLACEHOLDER_REGEX with the new information
      PLACEHOLDERS_REGEX = Regexp.union((CONTEXT_PLACEHOLDERS.keys + PLACEHOLDERS.keys).map do |key|
        Regexp.new(Regexp.escape(key))
      end).freeze
    end
  end
end
