# frozen_string_literal: true

require_relative "database/version"

module Gitlab
  module Platform
    # Namespace for this gem's own metadata. The libraries the gem owns keep their
    # original constant names under Gitlab::Database, so that moving a file into
    # this gem never changes a call site.
    module Database
    end
  end
end
