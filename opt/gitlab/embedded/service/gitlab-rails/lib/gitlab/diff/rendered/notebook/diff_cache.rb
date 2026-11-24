# frozen_string_literal: true

module Gitlab
  module Diff
    module Rendered
      module Notebook
        # Caches the parts of an IpynbDiff::Diff that DiffFile reads, keyed by the contents of the two blobs.
        class DiffCache
          # Change when the notebook transform (gems/ipynbdiff), DiffFile::IPYNB_DIFF_OPTIONS or the stored entry
          # layout change, so that a rolling deploy does not read old entries. The VERSION spec in
          # diff_cache_spec.rb fails when the rendered output changes, but not when the layout changes.
          VERSION = 2
          EXPIRATION = 1.hour
          # A timeout can come from a busy host, so render again sooner.
          TIMEOUT_EXPIRATION = 10.minutes
          # Serialized size, before compression.
          MAX_BYTES = 2.megabytes
          LOG_CACHE_HIT = 'IPYNB_DIFF_CACHE_HIT'
          LOG_CACHE_SKIPPED = 'IPYNB_DIFF_CACHE_SKIPPED'
          LOG_TOO_LARGE = 'IPYNB_DIFF_TOO_LARGE'
          PREFETCHED_KEY = :notebook_diff_cache_entries

          CachedNotebook = Struct.new(:as_text, :blocks)
          CachedDiff = Struct.new(:from, :to, :text) do
            # Only the text format is cached. Diffy::Diff#to_s also defaults to it.
            def to_s(format = :text)
              raise ArgumentError, "Unsupported format: #{format}" unless format.to_s == 'text'

              text
            end
          end

          # Reads the entries of these diff files in one call. #fetch then reads them from the request store.
          def self.prefetch(repository, diff_files)
            project = repository.project
            return unless project && diff_files.any? && Gitlab::SafeRequestStore.active?

            # DiffFile#notebook_diff skips truncated blobs before it reads the cache.
            keys = diff_files.filter_map do |file|
              next if file.old_blob&.truncated? || file.new_blob&.truncated?

              new(project: project, old_blob: file.old_blob, new_blob: file.new_blob).key
            end
            return if keys.empty?

            Gitlab::SafeRequestLoader.execute(resource_key: PREFETCHED_KEY, resource_ids: keys) do |missing_keys|
              # The cache store pipelines a cross-slot read on a Redis Cluster.
              Gitlab::Instrumentation::RedisClusterValidator.allow_cross_slot_commands do
                Rails.cache.read_multi(*missing_keys)
              end
            end
          end

          def initialize(project:, old_blob:, new_blob:)
            @project = project
            @old_blob = old_blob
            @new_blob = new_blob
          end

          # Returns the cached diff, or renders it with the block and caches it. A render that is too large or
          # times out leaves a marker instead, and later fetches return nil (the raw diff) until the marker expires.
          #
          # @yieldreturn [IpynbDiff::Diff, nil] the rendered diff
          # @return [CachedDiff, IpynbDiff::Diff, nil] an object with the methods of IpynbDiff::Diff that DiffFile reads
          def fetch(&render)
            cached = read

            if cached.nil? || render_after_foreground_timeout?(cached)
              render_and_write(&render)
            else
              load_cached(cached)
            end
          end

          def key
            ['notebook_diff', VERSION, project.id, old_blob&.id, new_blob&.id].join(':')
          end

          private

          attr_reader :project, :old_blob, :new_blob

          def read
            prefetched = Gitlab::SafeRequestStore[PREFETCHED_KEY]
            return prefetched[key] if prefetched&.key?(key)

            Rails.cache.read(key)
          end

          # Files of the same blobs in this request then read the written entry.
          def write(data, expires_in)
            Rails.cache.write(key, data, expires_in: expires_in)
            Gitlab::SafeRequestStore[PREFETCHED_KEY]&.store(key, data)
          end

          # Sidekiq renders with a longer timeout, so a timeout on the web does not stop it.
          def render_after_foreground_timeout?(cached)
            cached[:skipped] == :foreground_timeout && Gitlab::Runtime.sidekiq?
          end

          def load_cached(cached)
            if cached.key?(:skipped)
              log_event(LOG_CACHE_SKIPPED, skip_reason: cached[:skipped])
              return
            end

            log_event(LOG_CACHE_HIT)
            load(cached, cached_texts(cached))
          end

          def render_and_write
            notebook_diff = yield
            return unless notebook_diff

            texts = [notebook_diff.from.as_text, notebook_diff.to.as_text]
            data = dump(notebook_diff, texts)

            if Marshal.dump(data).bytesize > MAX_BYTES
              log_event(LOG_TOO_LARGE)
              skip(:too_large, EXPIRATION)
              return notebook_diff
            end

            write(data, EXPIRATION)
            load(data, texts)
          rescue Timeout::Error
            skip(Gitlab::Runtime.sidekiq? ? :background_timeout : :foreground_timeout, TIMEOUT_EXPIRATION)
            raise
          rescue IpynbDiff::TransformedNotebookTooLargeError
            skip(:too_large, EXPIRATION)
            raise
          end

          def skip(reason, expires_in)
            write({ skipped: reason }, expires_in)
          end

          def log_event(message, **fields)
            Gitlab::AppLogger.info(message: message, **fields)
          end

          def dump(notebook_diff, texts)
            text = notebook_diff.to_s(:text)
            # Most text diffs hold every line of both notebooks, so the notebooks need not be stored again.
            rebuildable = same_strings?(texts_from_diff(text), texts)

            {
              text: text,
              from: dump_notebook(notebook_diff.from, texts.first, rebuildable),
              to: dump_notebook(notebook_diff.to, texts.last, rebuildable)
            }
          end

          def dump_notebook(notebook, text, rebuildable)
            {
              as_text: (text unless rebuildable),
              source_lines: notebook.blocks.map { |block| block.fetch(:source_line) }
            }
          end

          # The entry stores the notebook texts only when they cannot be rebuilt from the text diff.
          def cached_texts(cached)
            texts = [cached[:from][:as_text], cached[:to][:as_text]]

            texts.first ? texts : texts_from_diff(cached[:text])
          end

          def load(data, texts)
            CachedDiff.new(
              load_notebook(data[:from], texts.first),
              load_notebook(data[:to], texts.last),
              data[:text]
            )
          end

          # DiffFile reads only the source line of each block.
          def load_notebook(data, text)
            blocks = data[:source_lines].map { |line| { source_line: line } }

            CachedNotebook.new(text, blocks)
          end

          # Context and removed lines form the old text, context and added lines the new one. Lines outside
          # the hunks are missing, so the caller compares the result with the original texts.
          def texts_from_diff(text)
            from = []
            to = []

            # The first two lines name the compared files.
            text.split("\n").drop(2).each do |line|
              content = line[1..]

              case line[0]
              when ' '
                from << content
                to << content
              when '-' then from << content
              when '+' then to << content
              end
            end

            # A notebook text ends with a newline unless it is empty.
            from << '' if from.any?
            to << '' if to.any?

            [from.join("\n"), to.join("\n")]
          end

          def same_strings?(strings, others)
            strings == others && strings.map(&:encoding) == others.map(&:encoding)
          end
        end
      end
    end
  end
end
