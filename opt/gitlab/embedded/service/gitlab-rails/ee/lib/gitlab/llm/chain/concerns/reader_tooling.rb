# frozen_string_literal: true

module Gitlab
  module Llm
    module Chain
      module Concerns
        module ReaderTooling
          def passed_content(_json)
            # we need to leave some characters for prompt and for history. We don't have access here
            # to full length of those, so we can reserve 40% of tokens for this.
            # It's 128_000 characters for prompt and 192_000 characters for
            # resource. It is estimated to cover 27428 words.
            resource_serialized = context
                                    .resource_serialized(content_limit: provider_prompt_class::MAX_CHARACTERS * 0.6)

            "Please use this information about identified #{resource_name}: #{resource_serialized}"
          rescue ArgumentError => error
            Answer.error_answer(
              error: error,
              context: context,
              error_code: "M5000"
            )
          end
        end
      end
    end
  end
end
