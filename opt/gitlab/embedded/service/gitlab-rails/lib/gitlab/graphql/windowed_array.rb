# frozen_string_literal: true

module Gitlab
  module Graphql
    # A list of `total` items that `loader.call(offset, limit)` loads one window at a time.
    WindowedArray = Struct.new(:total, :loader)
  end
end
