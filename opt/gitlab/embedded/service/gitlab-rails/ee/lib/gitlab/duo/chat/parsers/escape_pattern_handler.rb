# frozen_string_literal: true

module Gitlab
  module Duo
    module Chat
      module Parsers
        class EscapePatternHandler
          def initialize(text, link_info, escape_info, indexes)
            @text = text
            @link_info = link_info
            @escape_info = escape_info
            @indexes = indexes
          end

          def generate_pattern
            case @link_info[:method]
            when 'both'
              handle_both_pattern
            when 'front'
              handle_front_pattern
            when 'end'
              handle_end_pattern
            else
              {
                link: @link_info[:link],
                new_pattern: @escape_info[:pattern],
                starting_index: @link_info[:starting_index],
                ending_index: @link_info[:ending_index],
                add_to_index: 0,
                update_index: 0
              }
            end
          end

          private

          def handle_both_pattern
            if @escape_info[:contains_escaped_backticks]
              handle_escaped_backticks_both
            elsif @escape_info[:start_is_escaped]
              handle_escaped_start_both
            else
              {
                link: @link_info[:link],
                new_pattern: "`#{@escape_info[:pattern]}`",
                starting_index: @link_info[:starting_index],
                ending_index: @link_info[:ending_index],
                add_to_index: 2,
                update_index: 2
              }
            end
          end

          def handle_front_pattern
            if @escape_info[:contains_escaped_backticks]
              handle_escaped_backticks_front
            elsif @escape_info[:start_is_escaped]
              handle_escaped_start_front
            else
              {
                link: @link_info[:link],
                new_pattern: "`#{@escape_info[:pattern]}",
                starting_index: @link_info[:starting_index],
                ending_index: @link_info[:ending_index],
                add_to_index: 1,
                update_index: 1
              }
            end
          end

          def handle_end_pattern
            if @escape_info[:contains_escaped_backticks]
              handle_escaped_backticks_end
            elsif @escape_info[:start_is_escaped]
              handle_escaped_start_end
            else
              {
                link: @link_info[:link],
                new_pattern: "#{@escape_info[:pattern]}`",
                starting_index: @link_info[:starting_index],
                ending_index: @link_info[:ending_index],
                add_to_index: 1,
                update_index: 1
              }
            end
          end

          def handle_escaped_backticks_both
            @indexes[:space] += 1
            {
              link: @link_info[:link],
              new_pattern: " `#{@escape_info[:pattern]}`",
              starting_index: @link_info[:starting_index],
              ending_index: @link_info[:ending_index],
              add_to_index: 2,
              update_index: 2
            }
          end

          def handle_escaped_start_both
            @indexes[:space] += 1
            {
              link: "\\#{@link_info[:link]}",
              new_pattern: "\\ `#{@escape_info[:pattern]}`",
              starting_index: @link_info[:starting_index] - 1,
              ending_index: @link_info[:ending_index],
              add_to_index: 2,
              update_index: 2
            }
          end

          def handle_escaped_backticks_front
            @indexes[:space] += 1
            {
              link: "`#{@link_info[:link]}",
              new_pattern: "` `#{@escape_info[:pattern]}",
              starting_index: @link_info[:starting_index] - 1,
              ending_index: @link_info[:ending_index],
              add_to_index: 2,
              update_index: 2
            }
          end

          def handle_escaped_start_front
            @indexes[:space] += 1
            {
              link: "\\#{@link_info[:link]}",
              new_pattern: "\\ `#{@escape_info[:pattern]}",
              starting_index: @link_info[:starting_index] - 1,
              ending_index: @link_info[:ending_index],
              add_to_index: 2,
              update_index: 2
            }
          end

          def handle_escaped_backticks_end
            @indexes[:space] += 1
            {
              link: "`#{@link_info[:link]}",
              new_pattern: " `#{@escape_info[:pattern]}`",
              starting_index: @link_info[:starting_index] - 1,
              ending_index: @link_info[:ending_index] + 1,
              add_to_index: 1,
              update_index: 1
            }
          end

          def handle_escaped_start_end
            @indexes[:space] += 1
            {
              link: "\\#{@link_info[:link]}",
              new_pattern: "\\ #{@escape_info[:pattern]}`",
              starting_index: @link_info[:starting_index] - 2,
              ending_index: @link_info[:ending_index] + 1,
              add_to_index: 1,
              update_index: 1
            }
          end
        end
      end
    end
  end
end
