# frozen_string_literal: true

module Gitlab
  module Llm
    module Templates
      class SummarizeNewMergeRequest
        include Gitlab::Utils::StrongMemoize

        CHARACTER_LIMIT = 2000

        def initialize(user, project, params = {})
          @user = user
          @project = project
          @params = params
        end

        def to_prompt
          return if extracted_diff.blank?

          <<~PROMPT
            You are a code assistant, developed to help summarize code in non-technical terms.

            ```
            #{extracted_diff}
            ```

            The code above, enclosed by three ticks, is the code diff of a merge request.

            Write a summary of the changes in couple sentences, the way an expert engineer would summarize the
            changes using simple - generally non-technical - terms.

            You MUST ensure that it is no longer than 1800 characters. A character is considered anything, not only
            letters.
          PROMPT
        end

        private

        attr_reader :user, :project, :params

        def extracted_diff
          Gitlab::Llm::Utils::MergeRequestTool.extract_diff(
            source_project: source_project,
            source_branch: params[:source_branch],
            target_project: project,
            target_branch: params[:target_branch],
            character_limit: CHARACTER_LIMIT
          )
        end
        strong_memoize_attr :extracted_diff

        def source_project
          return project unless params[:source_project_id]

          source_project = Project.find_by_id(params[:source_project_id])

          if source_project.present? && Ability.allowed?(user, :create_merge_request_from, source_project)
            return source_project
          end

          project
        end
      end
    end
  end
end
