# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module AdditionalContext
      # What a flow's additional_context_resolver is called with. `primary_branch` is the
      # branch the run checks out, resolved from the requested source branch.
      class RuntimeContext < Data.define(:project, :resource, :goal, :primary_branch); end
    end
  end
end
