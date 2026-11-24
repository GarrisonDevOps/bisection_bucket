# frozen_string_literal: true

require "singleton"

module Labkit
  module UserExperienceSli
    # Fakes Labkit::UserExperienceSli::Experience.
    class Null
      include Singleton

      def id = 'null'

      def start(**_extra)
        return yield(self) if block_given?

        self
      end

      def resume(**_extra)
        return yield(self) if block_given?

        self
      end

      def observed(**_kwargs) = self
      def push_attributes!(*_args) = self
      def checkpoint(*_args) = self
      def complete(*_args) = self
      def error!(*_args) = self
      def rehydrate(*_args, **_kwargs) = self
      def to_h = {}
    end
  end
end
