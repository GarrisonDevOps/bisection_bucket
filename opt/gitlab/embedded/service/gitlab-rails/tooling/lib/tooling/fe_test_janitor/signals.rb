# frozen_string_literal: true

module Tooling
  module FeTestJanitor
    # Signal patterns used to classify RSpec examples.
    #
    # Keep signals indicate the example needs background jobs, third-party stubs,
    # or a real browser - things MSW cannot replace. `sign_in` and FactoryBot
    # records are not keep signals: MSW fixtures supply that data.
    #
    # Reframe signals indicate the example asserts DB state after a UI action.
    # Asserting the resulting UI change instead would unlock MSW.
    #
    # Migrate signals indicate the example only asserts on Vue/GraphQL-driven UI
    # and could be rewritten as a Jest + MSW integration test.
    module Signals
      KEEP = [
        # Background jobs
        { pattern: /\bperform_enqueued_jobs\b/, reason: "perform_enqueued_jobs (Sidekiq dependency)" },
        # Third-party HTTP stubs
        { pattern: /\bstub_request\b/, reason: "stub_request (third-party HTTP integration)" },
        # Session / cookie assertions
        { pattern: /\b(?:session|cookies)\[/, reason: "session/cookie assertion" },
        # Drag-and-drop
        { pattern: /\b(?:drag_to|drag_by|DragTo)\b/, reason: "drag-and-drop interaction" },
        # File uploads
        { pattern: /\b(?:attach_file|drop_file)\b/, reason: "file upload interaction" },
        # Accessibility checks
        { pattern: /\b(?:be_axe_clean|axe_check)\b/, reason: "accessibility check" },
        # Service object calls (ClassName.new(...).execute pattern), including calls split across lines
        { pattern: /[A-Z][A-Za-z:]+\.new\(.*?\)\s*\.execute\b/m, reason: "service object call" }
      ].freeze

      REFRAME = [
        { pattern: /\.reload\b/, reason: "reloads a record to assert DB state" },
        { pattern: /\bchange\s*[({]/, reason: "asserts a DB change with change {}" },
        { pattern: /\b[A-Z]\w*(?:::[A-Z]\w*)*\.(?:(?:count|first|last|find_by)\b|exists\?)/,
          reason: "queries a model to assert DB state" }
      ].freeze

      MIGRATE = [
        # Quarantine tag - flakiness often caused by race conditions MSW removes
        { pattern: /quarantine:/, reason: "quarantine tag detected" },
        # GraphQL mutation-driven interactions
        { pattern: /\b(?:execute_query|graphql_mutation|post_graphql_mutation)\b/,
          reason: "GraphQL mutation-driven interaction" },
        # Vue component UI assertions via data-testid selectors
        { pattern: /(?:have_css|have_selector|find_by_testid|within_testid)\s*[('"].*data-testid/,
          reason: "have_css/have_selector on Vue-rendered element (data-testid)" },
        # Generic have_css / have_selector on any rendered element
        { pattern: /\b(?:have_css|have_selector)\b/, reason: "have_css/have_selector on rendered element" }
      ].freeze
    end
  end
end
