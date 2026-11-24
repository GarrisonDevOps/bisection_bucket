# frozen_string_literal: true

module Analytics
  class LegacyAiUsageDatabaseWriteBuffer < DatabaseWriteBuffer
    LEGACY_PREFIX = 'usage_event_write_buffer_'

    private

    def buffer_key
      LEGACY_PREFIX + @buffer_key
    end
  end
end
