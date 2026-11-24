# frozen_string_literal: true

module Gitlab
  module MarkdownCache
    module RefreshBatch
      BATCH_SIZE = 100
      STATE_KEY = :gitlab_markdown_cache_refresh_batch

      Batch = Struct.new(:context, :ids_by_class)

      class << self
        def within
          return yield if pending

          batch = Batch.new(nil, Hash.new { |ids_by_class, class_name| ids_by_class[class_name] = Set.new })
          self.pending = batch

          begin
            yield
          ensure
            self.pending = nil
            Gitlab::ApplicationContext.with_raw_context(batch.context) { enqueue(batch.ids_by_class) } if batch.context
          end
        end

        def add(record)
          return enqueue(record.class.name => [record.id]) unless pending

          pending.context ||= Gitlab::ApplicationContext.current
          pending.ids_by_class[record.class.name] << record.id
        end

        private

        def enqueue(ids_by_class)
          ids_by_class.each do |class_name, ids|
            ids.each_slice(BATCH_SIZE) { |batch| RefreshWorker.perform_async(class_name, batch) }
          end
        end

        def pending
          ActiveSupport::IsolatedExecutionState[STATE_KEY]
        end

        def pending=(batch)
          ActiveSupport::IsolatedExecutionState[STATE_KEY] = batch
        end
      end
    end
  end
end
