# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Tools
        module MergeRequestReader
          class Executor < Identifier
            include Concerns::ReaderTooling

            RESOURCE_NAME = 'merge request'
            NAME = "MergeRequestReader"
            HUMAN_NAME = 'Merge Request Search'
            DESCRIPTION = 'Gets the content of the current merge request (also referenced as this or that, or MR) ' \
              'the user sees or a specific merge request identified by an ID or a URL.' \
              'In this context, "merge request" means part of work that is ready to be merged. ' \
              'Action Input for this tool should be the original question or merge request identifier.'

            EXAMPLE =
              <<~PROMPT
                Question: Please identify the author of !123 merge request
                Thought: You have access to the same resources as user who asks a question.
                  Question is about the content of a merge request, so you need to use "MergeRequestReader" tool to retrieve and read merge request.
                  Based on this information you can present final answer about merge request.
                Action: MergeRequestReader
                Action Input: Please identify the author of !123 merge request
              PROMPT

            PROVIDER_PROMPT_CLASSES = {
              ai_gateway: ::Gitlab::Llm::Chain::Tools::MergeRequestReader::Prompts::Anthropic,
              anthropic: ::Gitlab::Llm::Chain::Tools::MergeRequestReader::Prompts::Anthropic
            }.freeze

            PROJECT_REGEX = {
              'url' => MergeRequest.link_reference_pattern,
              'reference' => MergeRequest.reference_pattern
            }.freeze

            SYSTEM_PROMPT = Utils::Prompt.as_system(
              <<~PROMPT
                You can fetch information about a resource called: a merge request.
                A merge request can be referenced by url or numeric IDs preceded by symbol.
                A merge request can also be referenced by a GitLab reference. A GitLab reference ends with a number preceded by the delimiter ! and contains one or more /.
                ResourceIdentifierType can only be one of [current, iid, url, reference].
                ResourceIdentifier can be number, url. If ResourceIdentifier is not a number or a url, use "current".
                When you see a GitLab reference, ResourceIdentifierType should be reference.

                Make sure the response is a valid JSON. The answer should be just the JSON without any other commentary!
                References in the given question to the current issue can be also for example "this merge request" or "that merge request",
                referencing the merge request that the user currently sees.
                Question: (the user question)
                Response (follow the exact JSON response):
                ```json
                {
                  "ResourceIdentifierType": <ResourceIdentifierType>
                  "ResourceIdentifier": <ResourceIdentifier>
                }
                ```

                Examples of merge request reference identifier:

                Question: The user question or request may include https://some.host.name/some/long/path/-/merge_requests/410692
                Response:
                ```json
                {
                  "ResourceIdentifierType": "url",
                  "ResourceIdentifier": "https://some.host.name/some/long/path/-/merge_requests/410692"
                }
                ```

                Question: the user question or request may include: !12312312
                Response:
                ```json
                {
                  "ResourceIdentifierType": "iid",
                  "ResourceIdentifier": 12312312
                }
                ```

                Question: the user question or request may include long/groups/path!12312312
                Response:
                ```json
                {
                  "ResourceIdentifierType": "reference",
                  "ResourceIdentifier": "long/groups/path!12312312"
                }
                ```

                Question: Summarize the current merge request
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

            private

            def unit_primitive
              'merge_request_reader'
            end

            def reference_pattern_by_type
              PROJECT_REGEX
            end

            def by_iid(resource_identifier)
              return unless projects_from_context

              mrs = MergeRequest.in_projects(projects_from_context).iid_in(resource_identifier.to_i)

              mrs.first if mrs.one?
            end

            def resource_name
              RESOURCE_NAME
            end

            def get_resources(extractor)
              extractor.merge_requests
            end
          end
        end
      end
    end
  end
end
