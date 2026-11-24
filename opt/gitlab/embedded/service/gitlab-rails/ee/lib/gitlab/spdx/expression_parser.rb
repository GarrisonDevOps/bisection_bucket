# frozen_string_literal: true

require 'strscan'

module Gitlab
  module SPDX
    # Parses an SPDX license expression string into an ExpressionResult.
    #
    # Grammar (SPDX 3.x compound-expression subset):
    #
    #   expression        ::= or_expression
    #   or_expression     ::= and_expression ( OR and_expression )*
    #   and_expression    ::= with_expression ( AND with_expression )*
    #   with_expression   ::= simple_expression ( WITH simple_expression )?
    #   simple_expression ::= '(' expression ')' | license_id
    #   license_id        ::= ID_STRING '+'?
    #
    # Operator precedence (highest to lowest, per SPDX spec):
    #   1. + (binds tightest; captured as part of the token before any keyword operator is considered)
    #   2. WITH
    #   3. AND
    #   4. OR
    #   5. Parentheses for explicit grouping
    #
    # AND, OR, WITH are accepted in all-uppercase or all-lowercase only; mixed case (e.g. "And")
    # is treated as an identifier per the SPDX spec, causing a parse error.
    # On any parse error the result carries a :literal node with the raw input so callers
    # can still fall back to exact string matching.
    #
    # Note: SPDX registry validation is deferred to a follow-up; any well-formed id_string
    # is accepted here.
    class ExpressionParser
      ParseError = Class.new(StandardError)

      Token = Struct.new(:text, :offset, :type, keyword_init: true)

      # :id      - plain license identifier (e.g. "MIT")
      # :plus    - version-or-later identifier (e.g. "LGPL-2.0+"); base is value.chomp('+')
      # :with    - license with exception (e.g. "GPL-2.0 WITH Classpath-exception-2.0");
      #            value preserves original operator casing; children is [license_node, exception_node]
      # :and     - conjunction of licenses (dependency carries all)
      # :or      - disjunction of licenses (any one satisfies)
      # :literal - parse-error fallback carrying the raw input string
      Node = Struct.new(:type, :value, :children, keyword_init: true)

      # node:    root of the parse tree
      # literal: original unmodified input string, preserved for logging and fallback matching
      ExpressionResult = Struct.new(:node, :literal, keyword_init: true)

      MAX_NESTING_DEPTH = 50

      ID_STRING_RE = /[A-Za-z0-9\-.]+(?::LicenseRef-[A-Za-z0-9\-.]+)?[+]?/
      OPERATOR_RE = /\A(?:AND|and|OR|or|WITH|with)\z/
      TOKEN_RE = /#{ID_STRING_RE}|[()]/

      private_constant :MAX_NESTING_DEPTH, :ID_STRING_RE, :OPERATOR_RE, :TOKEN_RE

      def initialize(expression)
        @raw = expression.to_s.presence
        @tokens = []
        @pos = 0
      end

      def parse
        return ExpressionResult.new(node: Node.new(type: :literal, value: nil, children: []), literal: nil) unless @raw

        tokenize
        root = parse_or_expression
        raise ParseError, error_message("Unexpected token '#{current_token&.text}'") unless @pos >= @tokens.length

        ExpressionResult.new(node: root, literal: @raw)
      rescue ParseError
        ExpressionResult.new(node: Node.new(type: :literal, value: @raw, children: []), literal: @raw)
      end

      private

      def tokenize
        scanner = StringScanner.new(@raw)
        until scanner.eos?
          scanner.skip(/\s+/)
          break if scanner.eos?

          offset = scanner.charpos
          match = scanner.scan(TOKEN_RE)
          raise ParseError, error_message("Unexpected character '#{scanner.getch}'", offset) unless match

          @tokens << Token.new(text: match, offset: offset, type: classify_token(match))
        end
      end

      def classify_token(text)
        case text
        when '(' then :lparen
        when ')' then :rparen
        else text.match?(OPERATOR_RE) ? :operator : :id
        end
      end

      def error_message(msg, offset = nil)
        offset ||= current_token&.offset || @raw.length
        "Unable to parse expression '#{@raw}'. #{msg} at offset: #{offset}"
      end

      def parse_or_expression
        left = parse_and_expression
        while current_token_is_operator?('or')
          advance
          right = parse_and_expression
          left = Node.new(type: :or, value: nil, children: [left, right])
        end
        left
      end

      def parse_and_expression
        left = parse_with_expression
        while current_token_is_operator?('and')
          advance
          right = parse_with_expression
          left = Node.new(type: :and, value: nil, children: [left, right])
        end
        left
      end

      def parse_with_expression
        base = parse_simple_expression
        return base unless current_token_is_operator?('with')

        original_cased_operator = advance.text
        exception_node = parse_simple_expression
        Node.new(type: :with, value: original_cased_operator, children: [base, exception_node])
      end

      def parse_simple_expression
        @depth = (@depth || 0) + 1
        raise ParseError, error_message('Nesting too deep') if @depth > MAX_NESTING_DEPTH

        token = current_token
        raise ParseError, error_message('Unexpected end of expression') if token.nil?

        case token.type
        when :lparen
          advance
          inner = parse_or_expression
          raise ParseError, error_message('Unmatched parenthesis') unless current_token&.type == :rparen

          advance
          inner
        when :id
          advance
          node_type = token.text.end_with?('+') ? :plus : :id
          Node.new(type: node_type, value: token.text, children: [])
        else
          raise ParseError, error_message("Expected identifier or '(', got '#{token.text}'", token.offset)
        end
      ensure
        @depth -= 1
      end

      def current_token
        @tokens[@pos]
      end

      def advance
        token = current_token
        @pos += 1
        token
      end

      def current_token_is_operator?(keyword)
        current_token&.type == :operator && current_token.text.downcase == keyword
      end
    end
  end
end
