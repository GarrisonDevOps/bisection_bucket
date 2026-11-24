# frozen_string_literal: true

module ArtifactRegistry
  class Page
    attr_reader :nodes, :next_cursor, :prev_cursor, :permissions

    def initialize(nodes:, next_cursor: nil, prev_cursor: nil, permissions: nil)
      @nodes = Array(nodes).freeze
      @next_cursor = next_cursor
      @prev_cursor = prev_cursor
      @permissions = permissions
    end
  end
end
