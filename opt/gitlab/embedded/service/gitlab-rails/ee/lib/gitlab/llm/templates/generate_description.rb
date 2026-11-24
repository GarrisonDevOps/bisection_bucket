# frozen_string_literal: true

module Gitlab
  module Llm
    module Templates
      class GenerateDescription
        include Gitlab::Utils::StrongMemoize

        PROMPT_WITH_TEMPLATE = <<~PROMPT
        \n\nHuman: You are a helpful assistant
        Your job is to rewrite a text to follow the given template.

        Here's the text:

        <text>
        %<content>s
        </text>

        Here's the template:

        <template>
        %<template>s
        </template>

        Only respond with the rewritten text.

        Assistant:
        PROMPT

        PROMPT_WITHOUT_TEMPLATE = <<~PROMPT
        \n\nHuman: You are a helpful assistant.
        Your job is to write an issue description based off a text.

        Try to format the issue description appropriately.

        Here is the text:

        <text>
        %<content>s
        </text>

        Only respond with your issue description.

        Assistant:
        PROMPT

        def initialize(content, template: nil)
          @content = content
          @template = template
        end

        def to_prompt
          prompt = if template
                     PROMPT_WITH_TEMPLATE
                   else
                     PROMPT_WITHOUT_TEMPLATE
                   end

          format(prompt, content: content, template: template)
        end

        private

        attr_reader :content, :template
      end
    end
  end
end
