# frozen_string_literal: true

module Gitlab
  module Llm
    module Templates
      class ReviewMergeRequest
        def initialize(mr_title:, mr_description:, diffs_and_paths:, user:, files_content: {}, custom_instructions: [])
          @mr_title = mr_title
          @mr_description = mr_description
          @diffs_and_paths = diffs_and_paths
          @files_content = files_content
          @user = user
          @custom_instructions = custom_instructions
        end

        def to_prompt_inputs
          {
            mr_title: mr_title,
            mr_description: mr_description,
            diff_lines: all_diffs_formatted,
            # TODO: Remove full_file_intro after deprecating support for Claude 3.5 and Claude 3.7
            # Only required for backward compatibility with Prompt Version < 1.3.0
            full_file_intro: files_content.present? ? full_file_intro_text : "",
            full_content_section: files_content.present? ? full_content_section_text : "",
            custom_instructions_section: format_custom_instructions_section
          }
        end

        private

        def full_file_intro_text
          " You will also be provided with the original content of modified files (before changes) " \
            "to help you better understand the context and scope of changes. " \
            "Newly added files are not included as their full content is already in the diffs."
        end

        def full_content_section_text
          <<~SECTION.chomp
            <original_files>
            Use this context to better understand the changes and identify genuine issues in the code.

            Original file content (before changes):

            #{all_files_content_formatted}
            </original_files>
          SECTION
        end

        def format_custom_instructions_section
          return "" if custom_instructions.empty?

          instruction_items = custom_instructions.map do |instruction|
            # Convert include patterns array to comma-separated string, or "all files" if empty
            # Empty include patterns means apply to all files
            include_patterns = instruction[:include_patterns].join(", ").presence || "all files"

            # Convert exclude patterns array to comma-separated string, or "none" if empty
            exclude_patterns = instruction[:exclude_patterns].join(", ").presence || "none"

            "For files matching \"#{include_patterns}\" " \
              "(excluding: #{exclude_patterns}) - #{instruction[:name]}:\n" \
              "#{instruction[:instructions].strip}\n"
          end

          instructions_text = instruction_items.join("\n")
          <<~SECTION
            <custom_instructions>
            Apply these additional review instructions to matching files:

            #{instructions_text}

            IMPORTANT: Only apply each custom instruction to files that match its specified pattern. If a file doesn't match any custom instruction pattern, only apply the standard review criteria.

            When commenting based on custom instructions, format as:
            "According to custom instructions in '[instruction_name]': [your comment here]"

            Example: "According to custom instructions in 'Security Best Practices': This API endpoint should validate input parameters to prevent SQL injection."

            This formatting is only required for custom instruction comments. Regular review comments based on standard review criteria should NOT include this prefix.
            </custom_instructions>
          SECTION
        end

        def all_diffs_formatted
          diffs_and_paths.map do |path, raw_diff|
            formatted_diff = format_diff(raw_diff)
            %(<file_diff filename="#{path}">\n#{formatted_diff}\n</file_diff>)
          end.join("\n\n")
        end

        def all_files_content_formatted
          files_content.map do |path, content|
            %(<full_file filename="#{path}">\n#{content}\n</full_file>)
          end.join("\n\n")
        end

        def format_diff(raw_diff)
          lines = Gitlab::Diff::Parser.new.parse(raw_diff.lines)

          lines.map do |line|
            format_diff_line(line)
          end.join("\n")
        end

        def format_diff_line(line)
          if line.type == 'match'
            %(<chunk_header>#{line.text}</chunk_header>)
          else
            # NOTE: We are passing in diffs without the prefixes as the LLM seems to get confused sometimes and thinking
            # that's a part of the actual content.
            text = line.text(prefix: false)
            type = if line.added?
                     'added'
                   elsif line.removed?
                     'deleted'
                   else
                     'context'
                   end

            %(<line type="#{type}" old_line="#{line.old_line}" new_line="#{line.new_line}">#{text}</line>)
          end
        end

        attr_reader :mr_title, :mr_description, :diffs_and_paths, :files_content, :user, :custom_instructions
      end
    end
  end
end
