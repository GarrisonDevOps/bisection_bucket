# frozen_string_literal: true

module Gitlab
  module Database
    module PgAsh
      # Makes query text from pg_stat_statements safe to show to administrators.
      # pg_stat_statements keeps many statements, such as CREATE ROLE ... PASSWORD,
      # as typed, so only the statement types listed here show text, with every
      # value and comment replaced using PostgreSQL's own scanner.
      class QueryTextRedactor
        # Transaction commands are included because COMMIT can carry load while it
        # waits for the WAL.
        QUERY_STATEMENTS = %i[select_stmt insert_stmt update_stmt delete_stmt merge_stmt transaction_stmt].freeze

        # Schema changes and maintenance that take heavy locks or do heavy IO.
        MAINTENANCE_STATEMENTS = %i[
          alter_table_stmt cluster_stmt create_stmt create_table_as_stmt drop_stmt index_stmt lock_stmt
          refresh_mat_view_stmt reindex_stmt rename_stmt truncate_stmt vacuum_stmt
        ].freeze

        COMMENT_TOKENS = %i[C_COMMENT SQL_COMMENT].freeze

        # Strings in every quoting form, and numbers, as PostgreSQL's scanner reads them.
        VALUE_TOKENS = %i[SCONST USCONST BCONST XCONST ICONST FCONST].freeze

        # @param text [String] the text as pg_stat_statements stores it
        # @param limit [Integer] the most characters to return
        # @return [String, nil] the text with every value and comment replaced, at
        #   most limit characters long, or nil for a statement that shows no text,
        #   for text with a backslash, and for text that does not parse, such as
        #   <insufficient privilege>
        def self.redact(text, limit:)
          new(text, limit: limit).redact
        end

        def initialize(text, limit:)
          @text = text
          @limit = limit
        end

        def redact
          # With standard_conforming_strings off, \' does not end a string, but pg_query
          # reads text as if it were on, so part of a string could show as a name.
          return if text.include?('\\')
          return unless PgQuery.parse(text).tree.stmts.all? { |statement| shown?(statement.stmt) }

          replace_values_and_comments.truncate(limit).presence
        rescue PgQuery::ParseError, PgQuery::ScanError
          nil
        end

        private

        attr_reader :text, :limit

        def shown?(statement)
          case statement.node
          when *QUERY_STATEMENTS, *MAINTENANCE_STATEMENTS
            true
          when :copy_stmt
            # A file name, program command or option value can hold a secret, and
            # option values can be written as words, so only plain COPY to or from
            # the client, as pg_dump runs it, shows its text.
            statement.copy_stmt.filename.empty? && statement.copy_stmt.options.empty?
          else
            false
          end
        end

        # A space stands in for each comment, so the words around it stay apart.
        def replace_values_and_comments
          tokens = PgQuery.scan(text).first.tokens
          placeholder = nil
          replaced = +''
          position = 0

          tokens.each do |token|
            replacement =
              case token.token
              when *COMMENT_TOKENS
                ' '
              when *VALUE_TOKENS
                placeholder ||= highest_param(tokens)
                "$#{placeholder += 1}"
              end
            next unless replacement

            replaced << text.byteslice(position...token.start) << replacement
            position = token.end
          end

          (replaced << text.byteslice(position..)).strip
        end

        def highest_param(tokens)
          numbers = tokens.filter_map do |token|
            text.byteslice((token.start + 1)...token.end).to_i if token.token == :PARAM
          end

          numbers.max.to_i
        end
      end
    end
  end
end
