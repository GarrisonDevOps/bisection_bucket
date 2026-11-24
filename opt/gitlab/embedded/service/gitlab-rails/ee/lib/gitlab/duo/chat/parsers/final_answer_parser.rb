# frozen_string_literal: true

module Gitlab
  module Duo
    module Chat
      module Parsers
        class FinalAnswerParser
          DANGEROUS_ATTRIBUTES = %w[onerror onload onmouseover onclick alert].freeze
          ALLOWED_HOSTS = %w[docs.gitlab.com].freeze
          SEARCHED_HTML_TAGS = %w[a img source tool tool_name description example src script picture].freeze

          def self.sanitize(final_answer)
            apply_backtick_escapes = new(final_answer)
            apply_backtick_escapes.perform
          end

          def initialize(final_answer)
            @final_answer = final_answer
            @escaped_links = []
          end

          def perform
            return unless @final_answer

            sanitize_html_links
            sanitize_markdown_links
            sanitize_standard_urls # Standard URLs will need to be sanitized last

            # We add spaces between backticks in order to prevent being able to utilize a different number of opening
            # and closing backticks around text to inject malicious code. Markdown blocks are exempt from this rule.
            add_space_between_backticks
            add_space_to_escaped_backticks

            @final_answer
          end

          private

          def add_space_between_backticks
            text = @final_answer.dup

            markdown_blocks = extract_markdown_code_blocks(text)
            backtick_regex = /(?!:\\*)`{2,}/
            text = if markdown_blocks.empty?
                     text.gsub(backtick_regex) do |match|
                       match.gsub('`', ' `').strip
                     end
                   else
                     text.gsub(backtick_regex) do |match|
                       if within_markdown_block?(markdown_blocks, Regexp.last_match.begin(0), Regexp.last_match.end(0))
                         match
                       else
                         match.gsub('`', ' `').strip
                       end
                     end
                   end

            @final_answer = text
          end

          def add_space_to_escaped_backticks
            text = @final_answer.dup
            escaped_regex = /\\+`/

            markdown_blocks = extract_markdown_code_blocks(text)

            text = if markdown_blocks.empty?
                     text.gsub(escaped_regex) do |match|
                       match.gsub(/\\`/, '\\ `').strip
                     end
                   else
                     text.gsub(escaped_regex) do |match|
                       if within_markdown_block?(markdown_blocks, Regexp.last_match.begin(0), Regexp.last_match.end(0))
                         match
                       else
                         match.gsub(/\\`/, '\\ `').strip
                       end
                     end
                   end

            @final_answer = text
          end

          def sanitize_html_links
            text = @final_answer.dup

            markdown_blocks = extract_markdown_code_blocks(text)
            links_to_sanitize = {}
            addition_index = 0

            domain_allowlist_transformer = ->(env) do
              node = env[:node]
              env[:is_allowlisted] = true
              if node.elements
                node.elements.each do |element|
                  element_str = element.to_s
                  element_name = element.name
                  element_attributes = element.attributes
                  harmful_attribute = contains_harmful_attribute?(element_attributes)

                  # Edge case where Duo explains what an HTML A tag is.
                  if element_str.start_with?("<a>`")
                    # Add four to index to account for the Sanitize module auto closing the HTML A tag with "</a>"
                    addition_index += 4
                    next
                  elsif SEARCHED_HTML_TAGS.include?(element_name) || harmful_attribute

                    # Revert the Sanitize modules changing of "&" to "&amp;"
                    element_regex = escape_html_element_str(element_str)
                    element_str = escape_ampersands(element_str)

                    # TODO: Turn this into a hash instead of array to make it more descriptive on what each part is.
                    # NOTE: This will require updates to all of the sanitize methods as well.
                    element_indexes = find_all_regex_start_and_end_indices(text, element_regex)
                    element_indexes.each do |index|
                      starting_index = index[0] + addition_index
                      ending_index = index[1] + addition_index
                      ending_index += 1 if harmful_attribute

                      url_authorized = url_authorized?(element_str)
                      url_in_markdown_block = within_markdown_block?(markdown_blocks, starting_index, ending_index)

                      next if url_authorized || url_in_markdown_block

                      links_to_sanitize[element_str] ||= []
                      # TODO: These should be flattened at some point in the future. Right now there is an unnecessary
                      # level to the hash that could be cleaned up for all of the sanitize methods.
                      add_link_if_unique_position(links_to_sanitize[element_str], element_str, starting_index,
                        ending_index)
                    end
                  end
                end
              end
            end

            Sanitize.fragment(
              text,
              Sanitize::Config.merge(
                Sanitize::Config::RELAXED,
                elements: Sanitize::Config::RELAXED[:elements] + SEARCHED_HTML_TAGS,
                transformers: [domain_allowlist_transformer],
                remove_contents: false
              )
            )

            sanitize_list = determine_url_backtick_escape_needs(text, markdown_blocks, links_to_sanitize)

            text = apply_backtick_escapes(text, sanitize_list) if sanitize_list

            @final_answer = text.gsub(%r{&lt;}, '<').gsub(%r{&gt;}, '>')
          end

          def sanitize_markdown_links
            text = @final_answer.dup

            markdown_links = extract_and_index_markdown_links(text)
            markdown_blocks = extract_markdown_code_blocks(text)
            links_to_sanitize = {}

            markdown_links.each do |markdown_link|
              markdown_link.each do |item|
                link = item[:link]
                starting_index = item[:starting_position]
                ending_index = item[:ending_position]

                next if url_authorized?(link)
                next if within_markdown_block?(markdown_blocks, starting_index, ending_index)
                next if contains_safe_relative_urls?(link)

                links_to_sanitize[link] ||= []
                add_link_if_unique_position(links_to_sanitize[link], link, starting_index,
                  ending_index)
              end
            end

            sanitize_list = determine_url_backtick_escape_needs(text, markdown_blocks, links_to_sanitize)
            text = apply_backtick_escapes(text, sanitize_list) if sanitize_list

            @final_answer = text
          end

          def sanitize_standard_urls
            text = @final_answer.dup

            urls = extract_all_plaintext_urls(text)
            markdown_blocks = extract_markdown_code_blocks(text)
            links_to_sanitize = {}

            # Removes duplicate links found by URI module
            unique_links = urls.uniq

            unique_links.each do |url|
              url_authorized = url_authorized?(url)
              schema_only = schema_only?(url)

              next if url_authorized || schema_only

              url_regex = %r{#{Regexp.escape(url)}(?!/)}
              url_indexes = find_all_regex_start_and_end_indices(text, url_regex)

              url_indexes.each do |index|
                skip_occurrence = false
                starting_index = index[0]
                ending_index = index[1]
                url_indexes_in_another_link = url_indexes_in_another_link(text, url)
                within_markdown_block = within_markdown_block?(markdown_blocks, starting_index, ending_index)

                url_indexes_in_another_link.each do |indexes|
                  in_another_link = in_another_link?(indexes, starting_index, ending_index)
                  if in_another_link
                    skip_occurrence = true
                    break
                  end
                end

                next if skip_occurrence || within_markdown_block

                links_to_sanitize[url] ||= []
                add_link_if_unique_position(links_to_sanitize[url], url, starting_index, ending_index)
              end
            end

            sorted_links_to_sanitize = sort_and_remove_duplicate_standard_urls(links_to_sanitize)
            sanitize_list = determine_url_backtick_escape_needs(text, markdown_blocks, sorted_links_to_sanitize)

            text = apply_backtick_escapes(text, sanitize_list) if sanitize_list

            @final_answer = text
          end

          def schema_only?(url)
            return true if url == 'http://' || url == 'https://'

            false
          end

          def in_another_link?(searching_index, starting_index, ending_index)
            starting_index >= searching_index[0] && ending_index <= searching_index[1]
          end

          def extract_markdown_code_blocks(text)
            final_results = []
            code_block_regex = %r{
              ```         # Three backticks to start a code block
              \S*         # Zero or more non-whitespace characters (optional language specifier)
              \n          # A newline character
              [\s\S]*?    # Any characters (including newlines), non-greedy
              ```         # Three backticks to end the code block
              (?:\n|$)    # Either a newline character OR the end of the string
            }mux # Flag: multiline (m), and unicode (u), extended mode (x) for readability,

            text.scan(code_block_regex) do |_match|
              start_index = Regexp.last_match.begin(0)
              end_index = Regexp.last_match.end(0)
              final_results << [start_index, end_index]
            end
            final_results
          end

          def extract_and_index_markdown_links(text)
            regex = %r{
              \[.*?\]\(.*?\)           # Matches simple Markdown links: [text](url)
              |                        # OR
              \[                       # Opening square bracket
                (?:(?!\]).|\n)*        # Any characters (including newlines) that don't close the bracket
              \]                       # Closing square bracket
              \(                       # Opening parenthesis
                (?:(?!\)).|\n)*        # Any characters (including newlines) that don't close the parenthesis
              \)                       # Closing parenthesis
            }ux # Flag: Unicode (u), extended mode (x) for readability,

            markdown_links = text.enum_for(:scan, regex).map do |m|
              [m, Regexp.last_match.begin(0), Regexp.last_match.end(0)]
            end

            grouped_links = {}
            appearance_order = {}

            markdown_links.each do |(link, starting_position, ending_position)|
              grouped_links[link] ||= []
              appearance_order[link] ||= 0
              current_appearance = appearance_order[link] += 1
              grouped_links[link] << { link: link, starting_position: starting_position,
                                       ending_position: ending_position, appearance: current_appearance }
            end

            grouped_links.values
          end

          def extract_all_plaintext_urls(text)
            www_links = extract_www_links(text)
            ssh_urls = extract_ssh_urls(text)
            data_links = extract_data_links(text)
            custom_schema_urls = extract_custom_schema_links(text)
            malformed_ipv6_links = extract_malformed_ipv6_links(text)

            urls = URI.extract(text, %w[http https mailto ftp tel])
            urls += www_links unless www_links.empty?
            urls += ssh_urls unless ssh_urls.empty?
            urls += data_links unless data_links.empty?
            urls += custom_schema_urls unless custom_schema_urls.empty?
            urls += malformed_ipv6_links unless malformed_ipv6_links.empty?

            urls.map! do |url|
              url = remove_ending_backtick(url)
              url = url.chomp(')') if url.end_with?(')')
              url = url.chomp(')`') if url.end_with?(')`')
              url = url.chomp('.') if url.end_with?('.')
              url
            end

            urls
          end

          def remove_ending_backtick(url)
            regex = %r{
              (?:         # Start of a non-capturing group
                `         # A single backtick
                [^`\n]*   # Any character that is not a backtick or newline, zero or more times
                $         # End of the line
              )           # End of the non-capturing group
            }x # Flag: extended mode (x) for readability

            url.gsub(regex, '')
          end

          def url_indexes_in_another_link(search_string, url)
            escaped_url = Regexp.escape(url)

            regex = %r{
              (                         # Start of capturing group
                `                       # Opening backtick for inline code
                \[.*?\]                 # Markdown link text: [...] (non-greedy)
                \(                      # Opening parenthesis for link URL
                  (?:(?!\)).|\n)*       # Any character except closing parenthesis, or newline
                  #{escaped_url}        # The escaped URL we're looking for
                  (?:(?!\)).|\n)*       # Any character except closing parenthesis, or newline
                \)                      # Closing parenthesis for link URL
                `                       # Closing backtick for inline code
              |                         # OR
                `                       # Opening backtick for inline code
                <a\s+                   # Opening <a tag with whitespace
                (?:[^>]*?\s+)?          # Optional attributes before href
                href=["']               # href attribute start
                #{escaped_url}          # The escaped URL we're looking for
                ["']                    # Closing quote for href value
                .*?>                    # Any remaining attributes and closing >
                .*?                     # Link text (non-greedy)
                </a>                    # Closing </a> tag
                `                       # Closing backtick for inline code
              )                         # End of capturing group
            }ux # Flags: Unicode (u), extended mode (x) for readability

            search_string.enum_for(:scan, regex).map do |_m|
              [Regexp.last_match.begin(0), Regexp.last_match.end(0)]
            end
          end

          def extract_ssh_urls(text)
            regex = %r{
              (?<!\S)                 # Negative lookbehind: ensure no non-whitespace character before
              [a-zA-Z0-9_.-]+         # Match username (letters, numbers, underscore, dot, hyphen)
              @                       # Match the @ symbol
              [a-zA-Z0-9.-]+          # Match hostname (letters, numbers, dot, hyphen)
              :                       # Match the colon separator
              [a-zA-Z0-9_.-]+         # Match repository owner (letters, numbers, underscore, dot, hyphen)
              /                       # Match the forward slash separator
              [a-zA-Z0-9_.-]+         # Match repository name (letters, numbers, underscore, dot, hyphen)
              (?:\.git)?              # Optionally match .git at the end
              \S                      # Match any non-whitespace character at the end
            }x # Flag: extended mode (x) for readability

            text.scan(regex)
          end

          def extract_markdown_urls(text)
            regex = %r{
              \[                       # Opening square bracket for link text
                [^\]]*                 # Any characters except closing bracket (the link text)
              \]                       # Closing square bracket
              \(                       # Opening parenthesis for URL
                (                      # Start capturing group for the URL
                  [^)]*                # Any characters except closing parenthesis
                )                      # End capturing group
              \)                       # Closing parenthesis
            }x # Flag: extended mode (x) for readability

            text.scan(regex).flatten
          end

          def relative_url_without_embedded_urls?(url)
            # Check if the string starts with a slash
            return false unless url.start_with?('/')

            # Check for common URL schemes that might be embedded
            url_schemes = %r{
              (?:                                # Start of non-capturing group
                (?:https?|ftp|mailto|tel|        # Common web protocols
                   file|data|ssh|git)            # Other protocols
                :?//                             # Protocol separator (with optional colon)
              )                                  # End of non-capturing group
              |                                  # OR
              (?:                                # Start of non-capturing group
                www\.                            # URLs starting with www.
              )                                  # End of non-capturing group
            }ix # Flags: case insensitive (i), extended mode (x) for readability

            # Return true only if no URL schemes are found
            !url.match?(url_schemes)
          end

          def contains_safe_relative_urls?(text)
            # Extract URL portion of markdown link
            url = extract_markdown_urls(text).first
            return false unless url

            # Filter to only include safe relative URLs
            relative_url_without_embedded_urls?(url)
          end

          def extract_data_links(text)
            regex = %r{
              (?<!\S)                  # Negative lookbehind: ensure no non-whitespace character before
              data:                    # Match the "data:" prefix
              (?:
                [a-z]+/[a-z0-9\-+.]+   # Match MIME type (e.g., "image\/png")
              )?                       # MIME type is optional
              ;?                       # Optional semicolon after MIME type
              \w*                      # Match optional charset (e.g., "charset=US-ASCII")
              ,                        # Comma separator
              .*?                      # Match the data (non-greedy)
              \S+                      # Match any non-whitespace characters at the end
            }ix # Flag: case insensitive (i), extended mode (x) for readability

            text.scan(regex)
          end

          def extract_www_links(text)
            regex = %r{
              (?<!http://)            # Negative lookbehind: ensure "http://" doesn't precede
              (?<!https://)           # Negative lookbehind: ensure "https://" doesn't precede
              www\.                     # Match "www."
              [a-z0-9.\-]+              # Match domain name (letters, numbers, dots, hyphens)
              \.[a-z]{2,}               # Match top-level domain (at least two letters after a dot)
              [^\s]+                    # Match any non-whitespace characters (rest of the URL)
              (?=[\\/?$=+~_\-\.]*\s)    # Positive lookahead: URL ends with optional URL characters followed by space
              (?<![\),>"*])             # Negative lookbehind: URL doesn't end with ), comma, >, ", or *
            }ix # Flags: case insensitive (i), extended mode (x) for readability

            text.scan(regex)
          end

          def extract_malformed_ipv6_links(text)
            regex = %r{
              (?<!\S)                              # Ensure the link starts at a word boundary
              https?://                            # Match 'http:\/\/' or 'https:\/\/'
              \[                                   # Match exactly one opening square bracket
              (?:
                %[0-9a-fA-F]{2}                    # Match a percent sign followed by two hex digits
                |                                  # OR
                [0-9a-fA-F:]                       # Match any hex digit or colon (valid IPv6 chars)
                |                                  # OR
                \p{^ASCII}                         # Match any non-ASCII character (Unicode)
              ){2,}+                               # Match 2 or more of the above, possessively
              (?!\])                               # Ensure next char is not a closing bracket
              (?:
                [^\s\[]                            # Match any char except whitespace or '['
                |                                  # OR
                %[0-9a-fA-F]{2}                    # Match a percent-encoded character
                |                                  # OR
                \p{^ASCII}                         # Match any non-ASCII character
              )*                                   # Match zero or more of the above
              (?::\d+)?                            # Optionally match a colon and one or more digits (port)
              \S+                                  # Match one or more non-whitespace characters
              (?![\]\)])                           # Ensure next char is not ']' or ')'
            }ix # Flags: case insensitive (i), extended mode (x) for readability

            text.scan(regex)
          end

          def extract_custom_schema_links(text)
            regex = %r{
              (?<!\S)                 # Ensure the link starts at a word boundary
              [a-zA-Z]                # Match a letter at the start (custom schema must start with a letter)
              [a-zA-Z0-9+.\-@]*       # Match any number of letters, digits, +, ., -, or @ (rest of schema name)
              (?<!http|https)         # Negative lookbehind to ensure it's not 'http' or 'https'
              ://                     # Match the ':\/\/' separator
              \S+                     # Match one or more non-whitespace characters (the rest of the URL)
              (?![\]\)])              # Ensure next char is not ']' or ')'
            }ix # Flags: case insensitive (i), extended mode (x) for readability

            text.scan(regex)
          end

          def escape_html_element_str(str)
            str = escape_parentheses(str)
            str = escape_brackets(str)
            str = escape_ampersands(str)
            str = escape_question_mark(str)

            /#{str}/u
          end

          def escape_parentheses(str)
            str.gsub(/[\(\)]/) { |match| "\\#{match}" }
          end

          def escape_brackets(str)
            str.gsub(/[\[\]]/) { |match| "\\#{match}" }
          end

          def escape_ampersands(str)
            str.gsub(%r{&amp;}, '&')
          end

          def escape_question_mark(str)
            str.gsub(%r{\?}, '\?')
          end

          def sort_and_remove_duplicate_standard_urls(urls)
            sorted_links_to_sanitize = {}
            urls_array = urls.values.flatten.sort_by { |item| item[:starting_index] }

            sorted_links = urls_array.group_by { |entry| entry[:starting_index] }
                                     .values
                                     .map { |group| group.max_by { |entry| entry[:ending_index] } }
                                     .sort_by { |entry| entry[:link] }

            sorted_links.each do |value|
              sorted_links_to_sanitize[value[:link]] ||= []
              add_link_if_unique_position(sorted_links_to_sanitize[value[:link]], value[:link], value[:starting_index],
                value[:ending_index])
            end

            sorted_links_to_sanitize
          end

          def within_markdown_block?(markdown_blocks, starting_index, ending_index)
            return false if markdown_blocks.nil? || markdown_blocks.empty?

            markdown_blocks.each do |block|
              return true if starting_index >= block[0] && ending_index <= block[1]
            end

            false
          end

          def find_all_regex_start_and_end_indices(string, regex)
            indices = []

            string.scan(regex) do |_match|
              indices << [Regexp.last_match.begin(0), Regexp.last_match.end(0)]
            end

            indices
          end

          def url_authorized?(text)
            urls = URI.extract(text)
            urls.any? { |url| host_allowed?(url) }
          end

          def host_allowed?(url)
            if valid_url(url)
              host = URI.parse(url).host
              config_base_url = Gitlab.config.gitlab.base_url
              host == URI.parse(config_base_url).host || ALLOWED_HOSTS.include?(host)
            else
              false
            end
          end

          def valid_url(url)
            uri = URI.parse(url)
            %w[http https].include?(uri.scheme)
          rescue URI::BadURIError, URI::InvalidURIError
          end

          def contains_harmful_attribute?(element_attributes)
            return true if element_attributes.any? { |attr| DANGEROUS_ATTRIBUTES.include?(attr.first) }

            false
          end

          def determine_url_backtick_escape_needs(text, markdown_blocks, urls)
            Parsers::EscapeNeedsAnalyzer.new(text, markdown_blocks, urls.values.flatten, @escaped_links).analyze
          end

          def add_link_if_unique_position(links_array, link, starting_index, ending_index)
            new_link = { link: link, starting_index: starting_index, ending_index: ending_index }
            links_array << new_link unless links_array.any? do |existing_link|
              existing_link[:starting_index] == starting_index &&
                existing_link[:ending_index] == ending_index
            end
          end

          def apply_backtick_escapes(text, sanitize_list)
            indexes = { add: 0, space: 0, backticks_removed: 0 }
            unique_links = Set.new
            sanitize_list.values.flatten
                         .sort_by { |item| item[:starting_index] }
                         .each do |item|
              text = process_backtick_escape(text, item, indexes, unique_links)
            end

            text
          end

          def url_already_escaped?(start_index, end_index)
            @escaped_links.any? do |link_start, link_end|
              start_index >= link_start && end_index <= link_end
            end
          end

          def process_backtick_escape(text, item, indexes, unique_links)
            link_info = build_link_info(item, indexes)
            return text if skip_link?(link_info[:starting_index], link_info[:ending_index], unique_links)

            link_pattern = prepare_link_pattern(link_info[:link], indexes)
            escape_info = build_escape_info(text, link_info, link_pattern)

            apply_escape_pattern(text, link_info, escape_info, indexes, unique_links)
          end

          def build_link_info(item, indexes)
            {
              link: item[:link],
              method: item[:sanitize_method],
              starting_index: calculate_starting_index(item[:starting_index], indexes),
              ending_index: calculate_ending_index(item[:ending_index], indexes)
            }
          end

          def calculate_starting_index(index, indexes)
            index + indexes[:add] - indexes[:backticks_removed] - indexes[:space]
          end

          def calculate_ending_index(index, indexes)
            index + indexes[:add] - indexes[:backticks_removed] + indexes[:space]
          end

          def skip_link?(starting_index, ending_index, unique_links)
            url_already_escaped?(starting_index, ending_index) ||
              unique_links&.include?([starting_index, ending_index])
          end

          def prepare_link_pattern(link, indexes)
            back_tick_count = link_contains_backtick_count(link)
            indexes[:backticks_removed] += back_tick_count if back_tick_count
            remove_embedded_backticks(link)
          end

          def build_escape_info(text, link_info, link_pattern)
            {
              pattern: link_pattern,
              contains_escaped_backticks: contains_escaped_backtick(
                text[link_info[:starting_index] - 2...link_info[:ending_index]]),
              start_is_escaped: contains_backslash_before(
                text[link_info[:starting_index] - 1...link_info[:ending_index]])
            }
          end

          def apply_escape_pattern(text, link_info, escape_info, indexes, unique_links)
            escape_handler = Parsers::EscapePatternHandler.new(text, link_info, escape_info, indexes)
            pattern = escape_handler.generate_pattern

            text = replace_url_with_escaped_version(
              text,
              pattern[:link],
              pattern[:new_pattern],
              pattern[:starting_index],
              pattern[:ending_index]
            )

            update_tracking_data(link_info, pattern, indexes, unique_links)
            text
          end

          def update_tracking_data(link_info, pattern, indexes, unique_links)
            @escaped_links << [pattern[:starting_index], link_info[:ending_index]]
            indexes[:add] += pattern[:add_to_index]
            unique_links.add([pattern[:starting_index], link_info[:ending_index]])
            update_all_escaped_links_array(
              pattern[:starting_index],
              link_info[:ending_index],
              pattern[:update_index]
            )
          end

          def update_all_escaped_links_array(starting_index, _ending_index, index_count)
            @escaped_links.each do |link_array|
              next unless link_array[0] >= starting_index

              link_array[0] += index_count if @escaped_links.count > 1

              link_array[1] += index_count
            end
          end

          def contains_escaped_backtick(text_to_search)
            if text_to_search.start_with?(/\\+`/)
              true
            else
              false
            end
          end

          def contains_backslash_before(text_to_search)
            if text_to_search.start_with?('\\')
              true
            else
              false
            end
          end

          def remove_embedded_backticks(link)
            link.delete('`')
          end

          def link_contains_backtick_count(link)
            link.scan(/`/).count
          end

          def replace_url_with_escaped_version(text, url, new_pattern, start_index, end_index)
            before = text[0...start_index].to_s
            middle = text[start_index...end_index].to_s.gsub(url, new_pattern)
            after = text[end_index..].to_s
            before + middle + after
          end
        end
      end
    end
  end
end
