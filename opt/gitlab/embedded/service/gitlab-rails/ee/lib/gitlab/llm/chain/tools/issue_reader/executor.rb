# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Tools
        module IssueReader
          class Executor < Identifier
            include Concerns::ReaderTooling

            RESOURCE_NAME = 'issue'
            NAME = "IssueReader"
            HUMAN_NAME = 'Issue Search'
            DESCRIPTION = <<~PROMPT
            This tool retrieves the content of a specific issue
            ONLY if the user question fulfills the strict usage conditions below.

            **Strict Usage Conditions:**
            * **Condition 1: Issue ID Provided:** This tool MUST be used ONLY when the user provides a valid issue ID.
            * **Condition 2: Issue URL Context:** This tool MUST be used ONLY when the user is actively viewing a specific issue URL or a specific URL is provided by the user.

            **Do NOT** attempt to search for or identify issues based on descriptions, keywords, or user questions.

            **Action Input:**
            * The original question asked by the user.

            **Important:**  Reject any input that does not strictly adhere to the usage conditions above.
            Return a message stating you are unable to search for issues without a valid identifier.
            PROMPT

            EXAMPLE =
              <<~PROMPT
                Question: Please identify the author of #123 issue
                Thought: You have access to the same resources as user who asks a question.
                  Question is about the content of an issue, so you need to use "IssueReader" tool to retrieve and read issue.
                  Based on this information you can present final answer about issue.
                Action: IssueReader
                Action Input: Please identify the author of #123 issue
              PROMPT

            PROVIDER_PROMPT_CLASSES = {
              ai_gateway: ::Gitlab::Llm::Chain::Tools::IssueReader::Prompts::Anthropic,
              anthropic: ::Gitlab::Llm::Chain::Tools::IssueReader::Prompts::Anthropic
            }.freeze

            PROJECT_REGEX = {
              'url' => Issue.link_reference_pattern,
              'reference' => Issue.reference_pattern
            }.freeze

            SYSTEM_PROMPT = Utils::Prompt.as_system(
              <<~PROMPT
                You can fetch information about a resource called: an issue.
                An issue can be referenced by url or numeric IDs preceded by symbol.
                An issue can also be referenced by a GitLab reference. A GitLab reference ends with a number preceded by the delimiter # and contains one or more /.
                ResourceIdentifierType can only be one of [current, iid, url, reference].
                ResourceIdentifier can be number, url. If ResourceIdentifier is not a number or a url, use "current".
                When you see a GitLab reference, ResourceIdentifierType should be reference.

                Make sure the response is a valid JSON. The answer should be just the JSON without any other commentary!
                References in the given question to the current issue can be also for example "this issue" or "that issue",
                referencing the issue that the user currently sees.
                Question: (the user question)
                Response (follow the exact JSON response):
                ```json
                {
                  "ResourceIdentifierType": <ResourceIdentifierType>
                  "ResourceIdentifier": <ResourceIdentifier>
                }
                ```

                Examples of issue reference identifier:

                Question: The user question or request may include https://some.host.name/some/long/path/-/issues/410692
                Response:
                ```json
                {
                  "ResourceIdentifierType": "url",
                  "ResourceIdentifier": "https://some.host.name/some/long/path/-/issues/410692"
                }
                ```

                Question: the user question or request may include: #12312312
                Response:
                ```json
                {
                  "ResourceIdentifierType": "iid",
                  "ResourceIdentifier": 12312312
                }
                ```

                Question: the user question or request may include long/groups/path#12312312
                Response:
                ```json
                {
                  "ResourceIdentifierType": "reference",
                  "ResourceIdentifier": "long/groups/path#12312312"
                }
                ```

                Question: Summarize the current issue
                Response:
                ```json
                {
                  "ResourceIdentifierType": "current",
                  "ResourceIdentifier": "current"
                }
                ```

                Begin!
              PROMPT
            )

            PROMPT_TEMPLATE = [
              SYSTEM_PROMPT,
              Utils::Prompt.as_assistant("%<suggestions>s"),
              Utils::Prompt.as_user("Question: %<input>s")
            ].freeze

            def unit_primitive
              'issue_reader'
            end

            private

            def reference_pattern_by_type
              PROJECT_REGEX
            end

            def by_iid(resource_identifier)
              return unless projects_from_context

              issues = Issue.in_projects(projects_from_context).iid_in(resource_identifier.to_i)

              issues.first if issues.one?
            end

            def resource_name
              RESOURCE_NAME
            end

            def get_resources(extractor)
              extractor.issues
            end
          end
        end
      end
    end
  end
end
