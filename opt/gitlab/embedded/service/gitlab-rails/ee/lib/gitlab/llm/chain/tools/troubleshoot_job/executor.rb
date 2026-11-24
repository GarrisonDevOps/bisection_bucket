# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Tools
        module TroubleshootJob
          class Executor < SlashCommandTool
            extend ::Gitlab::Utils::Override
            include Concerns::JobLoggable

            # We use 1 Charater per 1 Token because we can't copy the tokenizer logic easily
            # So we go lower the characters per token to compensate for that.
            # For more context see: https://github.com/javirandor/anthropic-tokenizer and
            # https://gitlab.com/gitlab-org/gitlab/-/issues/474146
            APPROX_MAX_INPUT_CHARS = 100_000

            DEFAULT_PROMPT_VERSION = '^1.0.0'

            NAME = 'TroubleshootJob'
            RESOURCE_NAME = 'Ci::Build'
            HUMAN_NAME = 'Troubleshoot Job'
            DESCRIPTION = 'Useful tool to troubleshoot job-related issues.'
            EXAMPLE = "Question: My job is failing with an error. How can I fix it and figure out why it failed? " \
              'Picked tools: "TroubleshootJob" tool. ' \
              'Reason: The question is about troubleshooting a job issue. "TroubleshootJob" tool ' \
              'can process this question.'
            PROVIDER_PROMPT_CLASSES = {
              ai_gateway: ::Gitlab::Llm::Chain::Tools::TroubleshootJob::Prompts::Anthropic,
              anthropic: ::Gitlab::Llm::Chain::Tools::TroubleshootJob::Prompts::Anthropic
            }.freeze

            PROMPT_TEMPLATE = [
              Utils::Prompt.as_system(
                <<~PROMPT
                You are a Software engineer's or DevOps engineer's Assistant.
                You can explain the root cause of a GitLab CI verification job code failure from the job log.
                %<language_info>s
                PROMPT
              ),
              Utils::Prompt.as_user(
                <<~PROMPT.chomp
                You are tasked with analyzing a job log to determine why a job failed. Your goal is to explain the root cause of the failure in a way that any Software engineer could understand. Follow these steps carefully:

                1. Review the tail end of the job log provided within the <log> tags:

                <log>
                  %<selected_text>s
                </log>

                2. Analyze the job log carefully, focus on errors and failures. Ignore warning, and deprecation warnings, as they are often not relevant to this failure.

                3. Think through the analysis step by step. Consider the sequence of events in the log, the specific error messages, and how they relate to each other. Do not suggest fixing the test unless it's clearly the source of the problem.

                4. In your response, use the following structure:
                  a. Start with an H4 heading "Root cause of failure"
                  b. Explain the root cause of the failure
                  c. Use an H4 heading "Example Fix"
                  d. Provide an example fix or suggestions for resolution

                5. When explaining the root cause:
                  - Focus on actual errors, not warnings or deprecation messages
                  - Describe the chain of events leading to the failure
                  - Identify the specific line or component that triggered the failure
                  - Explain why this caused the job to fail

                6. When providing an example fix:
                  - If you can determine a specific code change, describe it in detail
                  - If you're unsure about the exact fix, provide general suggestions or options
                  - Emphasize that the actual project context may vary and your analysis is based solely on the provided job logs

                7. To prevent hallucination:
                  - Only refer to information explicitly present in the log
                  - If you're unsure about any aspect, clearly state your uncertainty
                  - Do not invent or assume details not present in the log
                  - If you cannot determine the root cause from the given information, state this clearly and explain why

                Remember, your analysis should be based solely on the information provided in the job log. Do not make assumptions about the broader system or codebase unless explicitly evidenced in the log. Begin your response with the "Root cause of failure" heading, skipping any preamble.
              PROMPT
              )
            ].freeze

            SLASH_COMMANDS = {
              '/troubleshoot' => {
                description: 'Troubleshoot a job based on the logs.',
                selected_code_without_input_instruction: 'Troubleshoot the job log.',
                selected_code_with_input_instruction: "Troubleshoot the job log. Input: %<input>s."
              }
            }.freeze

            def self.slash_commands
              SLASH_COMMANDS
            end

            def self.prompt_template
              PROMPT_TEMPLATE
            end

            override :prompt_version
            def prompt_version
              DEFAULT_PROMPT_VERSION
            end

            override :perform
            def perform
              unless job.trace.exist?
                return error_with_message(
                  _('There is no job log to troubleshoot.'),
                  error_code: 'M4005',
                  source: 'troubleshoot'
                )
              end

              track_troubleshoot_event
              super
            end

            private

            def allow_blank_message?
              true
            end

            def unit_primitive
              'troubleshoot_job'
            end

            def ai_request
              ::Gitlab::Llm::Chain::Requests::AiGateway.new(
                context.current_user,
                unit_primitive_name: :troubleshoot_job,
                tracking_context: tracking_context, root_namespace: job.project.root_ancestor)
            end

            def tracking_context
              {
                request_id: context.request_id,
                action: unit_primitive
              }
            end

            def selected_text_options
              {
                selected_text: truncated_job_log,
                language_info: language_info
              }
            end

            def truncated_job_log
              log_size_allowed = APPROX_MAX_INPUT_CHARS - prompt_size_without_log
              job_log.last(log_size_allowed)
            end

            def user_prompt
              PROMPT_TEMPLATE[1][1]
            end

            def prompt_size_without_log
              user_prompt.size
            end

            # For now, we'll just accept one job for our context since we have no batch
            # troubleshooting for jobs yet.
            def job
              context.resource
            end
            strong_memoize_attr :job

            def authorize
              # Enforce trace access on both paths; the usage-entitlement branch does not.
              return false unless context.current_user
              return false unless Ability.allowed?(context.current_user, :read_build_trace, job)

              if ::Feature.enabled?(:dap_external_trigger_usage_billing, context.current_user)
                context.current_user.allowed_to_use?(:troubleshoot_job, root_namespace: job.project.root_ancestor)
              else
                Ability.allowed?(context.current_user, :troubleshoot_job_with_ai, job)
              end
            end

            def resource_name
              RESOURCE_NAME
            end

            # Detects what code is used in the project
            # example return value:  "The repository code is written in Go, Ruby, Makefile, Shell and Dockerfile."
            def language_info
              language_names = job.project.repository_languages.map(&:name)
              return '' if language_names.empty?

              last_language = language_names.pop
              languages_comma_separated = language_names.join(', ')

              if language_names.size >= 1
                "The repository code is written in #{languages_comma_separated} and #{last_language}."
              else
                "The repository code is written in #{last_language}."
              end
            end

            def track_troubleshoot_event
              Gitlab::InternalEvents.track_event(
                'troubleshoot_job',
                user: context.current_user,
                job: job,
                project: job.project
              )
            end
          end
        end
      end
    end
  end
end
