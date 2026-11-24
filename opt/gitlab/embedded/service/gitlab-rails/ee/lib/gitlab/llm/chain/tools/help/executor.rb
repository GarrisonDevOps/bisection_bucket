# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Tools
        module Help
          class Executor < SlashCommandTool
            extend ::Gitlab::Utils::Override
            include Gitlab::DuoChatResourceHelper

            NAME = 'Help'
            HUMAN_NAME = 'Help'
            DESCRIPTION = 'Learn what Duo Chat can do'
            RESOURCE_NAME = nil
            ACTION = 'help'
            PROVIDER_PROMPT_CLASSES = {}.freeze

            SLASH_COMMANDS = {
              '/help' => {
                description: DESCRIPTION
              }
            }.freeze

            WEB_COPY = <<~COPY.freeze
GitLab Duo Chat is your personal AI-native assistant for boosting productivity. GitLab Duo Chat can help with:

* Questions about an issue or an epic, for example:
  * `Summarize this issue in 5 bullet points.`
  * `Rewrite the description of this epic to make to be more concise.`
* Questions about merge requests, for example:
  * `Which files and changes in this merge request should I review first?`
  * `Why was the .vue file changed in <merge request URL>?`
  * _Note: GitLab Duo Chat does not yet have the context of pipelines or commits in an MR._
* Explaining or generating code, for example:
  * `Create a regular expression for parsing IPv4 and IPv6 addresses in Python.`
  * `Create a CI/CD configuration to build and test Rust code.`
  * `Explain when this C function would cause a segmentation fault: sqlite3_prepare_v2()`
  * [On a code file, select the lines you want explained, then on the left side, select the question mark](#{::Gitlab::Routing.url_helpers.help_page_url('user/project/repository/code_explain.md')}).
* Questions about how GitLab works, for example:
  * `How do I add CI/CD variables to a project?`
* [Troubleshooting a failed pipeline](#{::Gitlab::Routing.url_helpers.help_page_url('user/gitlab_duo_chat/examples.md', anchor: 'troubleshoot-failed-cicd-jobs-with-root-cause-analysis')}) (Requires Ultimate and is part of GitLab Duo Enterprise):
  * On the job log page, select **Troubleshoot** or open GitLab Duo Chat and type `/troubleshoot`.
* [Explain a vulnerability](#{::Gitlab::Routing.url_helpers.help_page_url('user/application_security/vulnerabilities/_index.md', anchor: 'vulnerability-explanation')}) found by a SAST scanner (Requires Ultimate and is part of GitLab Duo Enterprise):
  * In the upper right, from the Resolve with merge request dropdown list, select **Explain vulnerability**, then select **Explain vulnerability**.
  * Or, open GitLab Duo Chat and type `/vulnerability_explain`.

Ask follow-up questions to dig deeper into or expand on the conversation with GitLab Duo. If you want to switch topics, type `/reset` and you might get better results.

Use GitLab Duo Chat in your IDE to explain, create, or refactor code, or to generate tests. After [you set up Chat in your IDE](#{::Gitlab::Routing.url_helpers.help_page_url('user/gitlab_duo_chat/_index.md', anchor: 'use-gitlab-duo-chat-in-the-web-ide')}) type `/help` in the IDE to learn how to use it.

Learn more about GitLab Duo Chat in the [documentation](#{::Gitlab::Routing.url_helpers.help_page_url('user/gitlab_duo_chat/examples.md')}).
            COPY

            IDE_COPY = <<~COPY.freeze
GitLab Duo Chat is your personal AI-native assistant for boosting productivity. You can ask GitLab Duo Chat questions about code by selecting the code and asking a question. GitLab Duo Chat can help with:

* Generating or change code, for example:
  * Select the code that you have a question about and ask your question.
  * `Create a regular expression for parsing IPv4 and IPv6 addresses in Python.`
  * `Create a CI/CD configuration to build and test Rust code.`
* Explaining code (you can also use `/explain`), for example:
  * Select the code you want explain and then ask questions like the following
  * `Explain when this C function would cause a segmentation fault: sqlite3_prepare_v2()`
  * `/explain why a static variable is used here`
* Refactoring code, (you can also use `/refactor`), for example:
  * Select the code you want refactored and then ask questions like the following
  * `/refactor to avoid memory leaks`
* Fixing code (you can also use `/fix`), for example:
  * Select the code you want fixed and then ask questions like the following
  * `/fix duplicate database inserts`
* Writing tests (you can also use `/tests`), for example:
  * Select the code you want to have tests written for and then ask questions like the following
  * `Write tests using the Boost.test framework`
  * `/tests`

Ask follow-up questions to dig deeper into or expand on the conversation with Duo. If you want to switch topics, type `/reset` and you might get better results.

Use GitLab Duo Chat in GitLab to ask questions about issues, epics, merge requests, comments, or to ask questions about GitLab or general DevSecOps questions. The GitLab Duo Chat button is on the top-right in group and project pages. To use it, ask `/help` in GitLab to learn how.

Learn more about GitLab Duo Chat can do in the [documentation](#{::Gitlab::Routing.url_helpers.help_page_url('user/gitlab_duo_chat/examples.md')}).
            COPY

            def self.slash_commands
              SLASH_COMMANDS
            end

            def perform
              content = command.platform_origin == SlashCommand::VS_CODE_EXTENSION ? IDE_COPY : WEB_COPY

              track_internal_event(
                'request_ask_help',
                namespace: namespace,
                project: project,
                user: context.current_user
              )

              Answer.new(status: :ok, context: context, content: content, tool: nil)
            end

            private

            def authorize
              true
            end

            def resource_name
              nil
            end
          end
        end
      end
    end
  end
end

::Gitlab::Llm::Chain::Tools::Help::Executor.prepend_mod
