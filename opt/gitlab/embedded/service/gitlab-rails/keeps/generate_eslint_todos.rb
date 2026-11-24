# frozen_string_literal: true

require_relative 'helpers/reviewer_roulette'

module Keeps
  # Regenerates the `.eslint_todo` lists, so that offenses fixed since the last run cannot be
  # reintroduced, and lists without offenses are deleted.
  #
  # You can run this keep with:
  #
  # ```
  # bundle exec gitlab-housekeeper -d -k Keeps::GenerateEslintTodos
  # ```
  class GenerateEslintTodos < ::Gitlab::Housekeeper::Keep
    ESLINT_TODO_DIR = '.eslint_todo'
    GENERATOR = %w[node scripts/frontend/generate_eslint_todo_list.mjs --all].freeze
    TITLE = 'Regenerate ESLint todo files'
    LABELS = %w[type::maintenance maintenance::workflow frontend].freeze
    DESCRIPTION = <<~MARKDOWN
      Offenses get fixed over time. To avoid reintroducing them, this MR regenerates the
      `.eslint_todo` files with `node scripts/frontend/generate_eslint_todo_list.mjs --all`.

      When reviewing, confirm:

      1. Only `.eslint_todo/` changed: entries removed or added, or todo files deleted.
      1. The `eslint` job passes.

      ### Responsibility of Reviewer

      These changes are generated, so we skip the initial review and ask a random ~frontend
      maintainer to review and merge. Fix any merge conflicts by rerunning the command above.
    MARKDOWN

    def each_identified_change
      change = ::Gitlab::Housekeeper::Change.new
      change.identifiers = change_identifiers
      yield(change)
    end

    def make_change!(change)
      ::Gitlab::Housekeeper::Shell.execute(*GENERATOR)

      if eslint_todo_files_unchanged?
        @logger.puts("No changes in the '#{ESLINT_TODO_DIR}' directory.")
        return
      end

      change.title = TITLE
      change.description = DESCRIPTION
      # The runner appends its own label after this method returns.
      change.labels = LABELS.dup
      change.changed_files = [ESLINT_TODO_DIR]
      change.reviewers = roulette.random_reviewer_for('maintainer::frontend', identifiers: change.identifiers)
      change
    end

    private

    def change_identifiers
      date = Date.current
      [self.class.name.demodulize, date.year.to_s, date.month.to_s]
    end

    def eslint_todo_files_unchanged?
      ::Gitlab::Housekeeper::Shell.execute('git', 'status', '--short', ESLINT_TODO_DIR).empty?
    end

    def roulette
      ::Keeps::Helpers::ReviewerRoulette.instance
    end
  end
end
