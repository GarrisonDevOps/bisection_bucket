# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module AdditionalContext
      module ClientContextBuilder
        def self.build(content:)
          return if content.blank?

          { "content" => content }
        end
      end
    end
  end
end
