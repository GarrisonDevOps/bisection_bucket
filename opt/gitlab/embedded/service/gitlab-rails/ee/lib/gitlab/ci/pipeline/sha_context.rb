# frozen_string_literal: true

module Gitlab
  module Ci
    module Pipeline
      class ShaContext
        attr_reader :before, :after, :source, :checkout, :target

        def initialize(before:, after:, source:, checkout:, target:)
          @before = before
          @after = after
          @source = source
          @checkout = checkout
          @target = target
        end
      end
    end
  end
end
