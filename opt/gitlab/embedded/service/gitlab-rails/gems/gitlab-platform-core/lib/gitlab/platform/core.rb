# frozen_string_literal: true

require_relative "core/version"

module Gitlab
  module Platform
    # Namespace for this gem's own metadata only. The libraries the gem owns keep
    # their original constant names directly under Gitlab, so that moving a file
    # into this gem never changes a call site.
    module Core
    end
  end
end
