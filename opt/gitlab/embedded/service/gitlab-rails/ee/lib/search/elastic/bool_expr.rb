# frozen_string_literal: true

module Search
  module Elastic
    BoolExpr = Struct.new(:must, :must_not, :should, :filter, :minimum_should_match) do # rubocop:disable Lint/StructNewOverride -- existing implementation
      def initialize
        super
        reset!
      end

      def reset!
        self.must     = []
        self.must_not = []
        self.should   = []
        self.filter   = []
        self.minimum_should_match = nil
      end

      def dup
        new_expr = self.class.new
        new_expr.must = must.deep_dup
        new_expr.must_not = must_not.deep_dup
        new_expr.should = should.deep_dup
        new_expr.filter = filter.deep_dup
        new_expr.minimum_should_match = minimum_should_match
        new_expr
      end

      def to_h
        super.reject { |_, value| value.blank? }
      end

      def empty?
        to_h.blank?
      end

      def to_bool_query
        return if empty?

        self.minimum_should_match ||= 1 if should.present?

        { bool: to_h }
      end

      def to_json(...)
        to_h.to_json(...)
      end

      def eql?(other)
        to_h.eql?(other.to_h)
      end
    end
  end
end
