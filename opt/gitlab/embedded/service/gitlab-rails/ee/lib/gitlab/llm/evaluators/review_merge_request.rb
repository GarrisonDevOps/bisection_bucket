# frozen_string_literal: true

module Gitlab
  module Llm
    module Evaluators
      class ReviewMergeRequest < Base
        extend Gitlab::Utils::Override
        include Gitlab::Utils::StrongMemoize

        private

        override :unit_primitive_name
        def unit_primitive_name
          :review_merge_request
        end

        override :model_metadata
        def model_metadata(_user)
          {
            provider: 'gitlab',
            feature_setting: 'review_merge_request'
          }
        end

        override :prompt_name
        def prompt_name
          'review_merge_request'
        end

        override :prompt_version
        def prompt_version
          PromptResolvers::ReviewMergeRequest.execute
        end
        strong_memoize_attr :prompt_version

        override :inputs
        def inputs
          ::Gitlab::Llm::Templates::ReviewMergeRequest.new(
            mr_title: options[:mr_title],
            mr_description: options[:mr_description],
            diffs_and_paths: parse_raw_diff(options[:diffs]),
            files_content: options[:files_content],
            user: user
          ).to_prompt_inputs
        end

        def parse_raw_diff(raw_diff)
          diffs = {}
          current_file = nil
          current_content = []

          raw_diff.each_line do |line|
            if line.start_with?('diff --git ')
              # Save the previous file's content
              if current_file && !current_content.empty?
                diffs[current_file] = current_content.join
                current_content = []
              end

              # Extract the new file path
              match = line.match(%r{diff --git a/.+ b/(.+)})
              current_file = match[1] if match

              # Start collecting content for this file
              current_content << line
            elsif current_file
              # Add line to current file's content
              current_content << line
            end
          end

          # Add the last file's content
          diffs[current_file] = current_content.join if current_file && !current_content.empty?
          diffs
        end
      end
    end
  end
end
