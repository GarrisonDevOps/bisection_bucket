# frozen_string_literal: true

module ClickHouse # rubocop:disable Gitlab/BoundedContexts -- existing module
  # The gem calls http_post_proc identically for select and execute, so we
  # flag select calls here to keep query limits off writes and to let
  # Gitlab::Metrics::Subscribers::ClickHouse tell select from execute.
  module ReadOnlyMarker
    KEY = :click_house_select_query

    def self.active?
      ActiveSupport::IsolatedExecutionState[KEY] == true
    end

    def select(...)
      previous = ActiveSupport::IsolatedExecutionState[KEY]
      ActiveSupport::IsolatedExecutionState[KEY] = true
      super
    ensure
      ActiveSupport::IsolatedExecutionState[KEY] = previous
    end
  end
end
