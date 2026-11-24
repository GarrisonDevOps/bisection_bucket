# frozen_string_literal: true

module Ai
  module DuoWorkflows
    # The part of the gateway's Poetry constraints (ai-assist lib/version.py) that
    # flow versions use: an exact version, or a caret range that, like the gateway,
    # admits stable versions only. Any other constraint is unmet.
    module FlowVersionConstraint
      STABLE_VERSION = /\A\d+\.\d+\.\d+\z/
      # Poetry's caret below 1.0.0 narrows to the minor; no flow uses it, so it is unmet too.
      CARET_RANGE = /\A\^(?<floor>[1-9]\d*\.\d+\.\d+)\z/

      def self.satisfied_by?(version, constraint)
        return false unless version.is_a?(String) && constraint.is_a?(String)
        return false if version.empty? || constraint.empty?
        return true if version == constraint

        floor = CARET_RANGE.match(constraint)&.[](:floor)
        return false unless floor && STABLE_VERSION.match?(version)

        version = Gem::Version.new(version)
        floor = Gem::Version.new(floor)

        version >= floor && version.segments.first == floor.segments.first
      end
    end
  end
end
