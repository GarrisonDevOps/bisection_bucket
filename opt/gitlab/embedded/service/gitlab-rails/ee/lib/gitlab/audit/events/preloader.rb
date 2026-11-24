# frozen_string_literal: true

module Gitlab
  module Audit
    module Events
      class Preloader
        # `author` and `entity` are BatchLoader backed, so touching them here lets a
        # whole page of events resolve in one query each instead of per row.
        def self.preload!(audit_events)
          audit_events.tap do |audit_events|
            audit_events.each do |audit_event|
              audit_event.lazy_author
              audit_event.entity
            end
          end
        end
      end
    end
  end
end
