# frozen_string_literal: true

module Gitlab
  module Duo
    module Chat
      module Parsers
        class EscapeNeedsAnalyzer
          def initialize(text, markdown_blocks, urls, escaped_links)
            @text = text
            @markdown_blocks = markdown_blocks
            @urls = urls.sort_by { |item| item[:starting_index] }
            @escaped_links = escaped_links
            @required_escapes = Hash.new { |h, k| h[k] = [] }
            @previous_url_info = []
            @escape_counts = { front: 0, back: 0 }
          end

          def analyze
            return if @text.nil?

            @urls.each do |url|
              process_url(url)
            end
            @required_escapes
          end

          private

          def process_url(url)
            link_data = extract_link_data(url)
            escape_requirements = determine_escape_requirements(link_data)
            return reset_previous_info if skip_url?(escape_requirements)

            process_escape_requirements(link_data, escape_requirements)
          end

          def extract_link_data(url)
            {
              link: url[:link],
              starting_index: url[:starting_index],
              ending_index: url[:ending_index]
            }
          end

          def determine_escape_requirements(link_data)
            {
              beginning: determine_beginning_requirement(link_data),
              ending: determine_ending_requirement(link_data),
              already_escaped: regex_already_backtick_escaped?(
                @text,
                link_data[:link],
                link_data[:starting_index],
                link_data[:ending_index]
              ),
              starting_index: link_data[:starting_index],
              ending_index: link_data[:ending_index]
            }
          end

          def determine_beginning_requirement(link_data)
            if url_beginning_escaped?(link_data[:starting_index])
              @escape_counts[:back] += 1
              return true
            end

            if @previous_url_info.empty?
              first_url_needs_beginning_backtick?(
                @text,
                @markdown_blocks,
                link_data[:link],
                link_data[:starting_index],
                link_data[:ending_index]
              )
            else
              handle_subsequent_url_beginning(link_data)
            end
          end

          def handle_subsequent_url_beginning(link_data)
            @previous_url_info[1] += 1 unless @previous_url_info[3]

            subsequent_url_needs_beginning_backtick?(
              @text,
              @markdown_blocks,
              @previous_url_info,
              link_data[:link],
              link_data[:starting_index],
              link_data[:ending_index]
            )
          end

          def determine_ending_requirement(link_data)
            first_url_needs_ending_backtick?(
              @text,
              link_data[:link],
              link_data[:starting_index],
              link_data[:ending_index]
            )
          end

          def skip_url?(requirements)
            (requirements[:already_escaped] &&
              !requirements[:beginning] &&
              !requirements[:ending]) ||
              url_already_escaped?(
                requirements[:starting_index],
                requirements[:ending_index]
              )
          end

          def process_escape_requirements(link_data, requirements)
            escape_type = determine_required_escape_type(
              requirements[:beginning],
              requirements[:ending],
              link_data[:link],
              link_data[:starting_index],
              link_data[:ending_index]
            )

            update_escape_counts(escape_type)
            update_previous_info(link_data, requirements)
            add_to_required_escapes(escape_type)
          end

          def update_escape_counts(escape_type)
            backticks = count_required_backticks(escape_type)
            return unless backticks

            @escape_counts[:front] += backticks[:front_escapes_required]
            @escape_counts[:back] += backticks[:end_escapes_required]
          end

          def update_previous_info(link_data, requirements)
            @previous_url_info = [
              link_data[:starting_index],
              link_data[:ending_index],
              requirements[:beginning],
              requirements[:ending]
            ]
          end

          def add_to_required_escapes(escape_type)
            escape_type.each do |method, list|
              @required_escapes[method] ||= []
              @required_escapes[method] += list
            end
          end

          def reset_previous_info
            @previous_url_info = []
          end

          def determine_required_escape_type(requires_beginning, requires_ending, link, starting_index, ending_index)
            sanitize_list = {}

            sanitize_method = if requires_beginning && requires_ending
                                'both'
                              elsif requires_beginning && !requires_ending
                                'front'
                              elsif !requires_beginning && requires_ending
                                'end'
                              else
                                'none'
                              end

            sanitize_list[sanitize_method] ||= []
            sanitize_list[sanitize_method] << { sanitize_method: sanitize_method, link: link,
                                                starting_index: starting_index, ending_index: ending_index }

            sanitize_list
          end

          def count_required_backticks(determine_required_escape_type)
            if determine_required_escape_type["both"]
              { front_escapes_required: 1, end_escapes_required: 1 }
            elsif determine_required_escape_type["front"]
              { front_escapes_required: 1, end_escapes_required: 0 }
            elsif determine_required_escape_type["end"]
              { front_escapes_required: 0, end_escapes_required: 1 }
            else
              { front_escapes_required: 0, end_escapes_required: 0 }
            end
          end

          def first_url_needs_beginning_backtick?(text, markdown_blocks, link, starting_index, ending_index)
            if markdown_blocks.empty?
              text = text[0...ending_index]
            else
              previous_markdown_block = []
              markdown_blocks.each_with_index do |markdown_block, index|
                if ending_index < markdown_block[0] && previous_markdown_block.empty? && index == 0
                  text = text[0...ending_index]
                  break
                elsif starting_index > markdown_block[1]
                  if index < markdown_blocks.length - 1
                    previous_markdown_block = markdown_block
                    next
                  end
                elsif (ending_index < markdown_block[0]) && (starting_index > previous_markdown_block[1])
                  text = text[previous_markdown_block[1]...ending_index]
                  break
                end

                text = text[markdown_block[1]...ending_index]
              end
            end

            needs_beginning_backtick?(text, link)
          end

          def subsequent_url_needs_beginning_backtick?(
            text, markdown_blocks, previous_url_escaped_indexes, link,
            starting_index, ending_index
          )
            prior_end_index = previous_url_escaped_indexes[1]

            return needs_beginning_backtick?(text[prior_end_index...ending_index], link) if markdown_blocks.empty?

            markdown_blocks.each do |markdown_block|
              if ending_index < markdown_block[0] ||
                  (starting_index > markdown_block[1] && prior_end_index > markdown_block[1])
                return needs_beginning_backtick?(text[prior_end_index...ending_index], link)
              elsif starting_index > markdown_block[1] && prior_end_index < markdown_block[1]
                return needs_beginning_backtick?(text[markdown_block[1]...ending_index], link)
              end
            end

            needs_beginning_backtick?(text[prior_end_index...ending_index], link)
          end

          def first_url_needs_ending_backtick?(text, link, starting_index, ending_index)
            text = text[starting_index...ending_index + 1]
            needs_ending_backtick?(text, link)
          end

          def needs_beginning_backtick?(text, link)
            return true unless text

            regex = Regexp.escape(link)
            backtick_regex = %r{.*(?=#{regex}$)}
            contains_backtick = text.match(backtick_regex)
            if contains_backtick
              contains_backtick_response = contains_backtick[0]
              escaped_backtick_regex = /\\+`/
              contains_backtick_response.scan(escaped_backtick_regex)

              backtick_count = contains_backtick_response.count('`')
              return true if backtick_count.even?

              false
            else
              true
            end
          end

          def needs_ending_backtick?(text, link)
            return false unless text

            escaped_regex = Regexp.escape(link)
            ending_backticks_regex = /(#{escaped_regex})(?!`)/
            text.match?(ending_backticks_regex)
          end

          def regex_already_backtick_escaped?(text, regex, starting_index, ending_index)
            text = if starting_index == 0
                     text[0...ending_index + 1]
                   else
                     # Protect against possible negative starting index
                     start_index = [starting_index - 1, 0].max
                     text[start_index...ending_index + 1]
                   end

            return false unless text

            regex = Regexp.escape(regex)
            already_escaped_regex = /`#{regex}`/
            text.match?(already_escaped_regex)
          end

          def url_already_escaped?(start_index, end_index)
            @escaped_links.any? do |link_start, link_end|
              start_index >= link_start && end_index <= link_end
            end
          end

          def url_beginning_escaped?(start_index)
            @escaped_links.any? do |_link_start, link_end|
              start_index == link_end
            end
          end
        end
      end
    end
  end
end
