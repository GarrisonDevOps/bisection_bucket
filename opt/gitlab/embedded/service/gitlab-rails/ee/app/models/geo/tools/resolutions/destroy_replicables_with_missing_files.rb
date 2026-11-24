# frozen_string_literal: true

module Geo
  module Tools
    module Resolutions
      # SPIKE (gitlab-org/gitlab#602803): destroys records on the primary whose file is gone
      # from storage, which is why their verification fails with "File is not checksummable".
      # Secondaries report the same records as "The file is missing on the Geo primary site"
      # (see ee/lib/gitlab/geo/replication/blob_downloader.rb).
      #
      # Detection is wide and resolution is narrow on purpose:
      #
      # - Detection reports a count for every verification-enabled blob replicable, so one
      #   cleanup_check shows the whole blast radius.
      # - Only DESTROYABLE_MODELS are destroyed, because those are the types the troubleshooting
      #   docs bless as safe to delete wholesale. Every other type is reported for manual
      #   cleanup, because deleting those has consequences the docs spell out per type (LFS
      #   objects shared between projects, published pages, and so on).
      #
      # Primary-side and genuinely destructive: it is gated behind DRY_RUN=false and, for a real
      # iteration, needs the data-deletion review. Four things stand between a matching row and
      # deletion: the narrow catalog pattern, DEFAULT_MIN_RETRY_COUNT recorded failures, a
      # per-record resource_exists? check against storage, and a recovery dump written before
      # the first destroy.
      #
      # We read the verification state tables (Geo::UploadState, Geo::JobArtifactState, ...)
      # rather than the model tables. verification_state is indexed on every state table and
      # failed rows are a small subset, so we page the failed rows instead of walking ~20 wide,
      # partitioned model tables on every check. The ILIKE match on top is not index-backed, so
      # it is deliberately applied to the already narrow failed set, only on demand, and with a
      # COUNT_LIMIT so detection cannot run away on a site with many failures.
      class DestroyReplicablesWithMissingFiles < Base
        # Destroying a record propagates the deletion to every Geo site, so it is only enabled
        # for the data types with a documented cleanup path. destroy, not delete_all: the
        # after_destroy hook in Geo::ReplicableModel is what creates the deletion event, and for
        # job artifacts it is also what keeps project statistics in step.
        #
        # Matched by ancestry rather than by name, so the Geo::*Upload partition models
        # (Geo::ProjectUpload and friends, which subclass ::Upload) stay destroyable once they
        # own verification instead of silently degrading to "needs manual cleanup".
        # See https://gitlab.com/groups/gitlab-org/-/work_items/20933 and
        # https://gitlab.com/gitlab-org/gitlab/-/work_items/589924.
        DESTROYABLE_MODELS = [::Upload, ::Ci::JobArtifact].freeze

        # Counting stops here per data type. The ILIKE is not index-backed, so the scan is
        # bounded by the number of failed rows, and on a site with many of those an exact
        # total is both expensive and useless: an operator deciding whether to run this needs
        # an order of magnitude, not a precise figure. Callers render a capped count as "N+".
        COUNT_LIMIT = 10_000

        # How many recorded verification failures a record needs before it is a cleanup
        # candidate. Verification backoff (Delay#next_retry_time) saturates near an hour and
        # the batch worker runs on a cron, so five failures means the file was absent across
        # several independent attempts spread over a meaningful window, rather than during one
        # blip. It does not prove the storage itself was healthy throughout - a multi-hour
        # outage drives the counter up too - so this narrows the transient-failure window
        # rather than closing it, and the per-record resource_exists? check immediately before
        # each destroy remains the last guard.
        #
        # verification_retry_count is the only durable signal available: there is no
        # first-failed-at column, because verified_at is rewritten on every attempt.
        DEFAULT_MIN_RETRY_COUNT = 5

        def initialize(error_type, **options)
          super

          # 0 is truthy in Ruby, so an explicit 0 disables the gate rather than falling back.
          @min_retry_count = options[:min_retry_count] || DEFAULT_MIN_RETRY_COUNT
          @skipped_count = 0
          @failed_count = 0
        end

        def affected_count
          counts.values.sum
        end

        def count_capped?
          counts.values.any? { |count| count >= COUNT_LIMIT }
        end

        def sample(limit: 5)
          return [] if inactive?

          samples = destroyable_counts.keys.flat_map do |model|
            key = model_id_column(model)

            matching(verification_state_class(model).all)
              .order(key => :asc).limit(limit).pluck(key).map do |id|
              "#{model.name} ##{id}"
            end
          end

          samples.first(limit) + manual_lines
        end

        def apply(limit: nil)
          return 0 if inactive?
          return 0 if destroyable_counts.empty?

          destroyed = 0
          remaining = limit

          # Opened before the first destroy and not rescued: if the recovery dump cannot be
          # written, nothing is destroyed, because the rows it deletes are otherwise only
          # recoverable from a backup.
          open_recovery_dump do
            destroyable_counts.each_key do |model|
              each_matching_batch(model) do |ids|
                destroyed_now = destroy_records(model, ids, remaining)

                destroyed += destroyed_now
                remaining -= destroyed_now if remaining

                break if remaining && remaining <= 0
              end

              break if remaining && remaining <= 0
            end
          end

          destroyed
        end

        def summary(count)
          messages = ["Destroyed #{count} records whose file is missing on the primary."]

          messages << "Skipped #{@skipped_count} records because their file is still in storage." if @skipped_count > 0

          messages << "#{@failed_count} records could not be destroyed, see the Geo log." if @failed_count > 0

          if @recovery_dump_path
            messages << "Recovery dump: #{@recovery_dump_path}. Each line is a destroyed row; " \
              "restoring one brings the record back, but not its file."
          end

          messages.concat(manual_lines).join("\n")
        end

        private

        def pattern
          error_type.match_pattern
        end

        # Primary-only. cleanup_check calls detect on every catalog entry regardless of site, so
        # without this a secondary would query every state table to find nothing: the primary's
        # verification state is only populated on the primary.
        def inactive?
          pattern.blank? || !Gitlab::Geo.primary?
        end

        # One substring predicate on purpose. The catalog pattern is narrow enough that the
        # sibling failure "File is not checksummable - <Model> <id> is excluded from
        # verification" cannot match, so this needs no second (negated) pattern to filter those
        # healthy records back out.
        #
        # The retry-count gate is applied here rather than only before destroying, so that the
        # count, the sample and the destruction all describe the same set. Applying it later
        # would make cleanup_check report one number and resolve act on another.
        def matching(relation)
          relation = relation.with_verification_failure_matching(pattern)

          # Skipped entirely at 0 rather than chained as "at least 0": the scope excludes NULL
          # counts, so chaining it would still filter out records that have never recorded a
          # retry, and 0 is how an operator asks for no gate at all.
          return relation if @min_retry_count == 0

          relation.with_verification_retry_count_at_least(@min_retry_count)
        end

        # { model class => number of records whose verification failed with this error }.
        # Memoized because the count, the sample and the summary all read it.
        def counts
          @counts ||= if inactive?
                        {}
                      else
                        model_classes.index_with { |model| matching_count(model) }
                                     .reject { |_model, count| count == 0 }
                      end
        end

        # LIMIT lets Postgres stop scanning once the cap is reached. The relation carries no
        # order, select or group, so the limit survives into the generated COUNT.
        def matching_count(model)
          matching(verification_state_class(model).all).limit(COUNT_LIMIT).count
        end

        def destroyable_counts
          counts.select { |model, _count| destroyable?(model) }
        end

        def destroyable?(model)
          DESTROYABLE_MODELS.any? { |destroyable| model <= destroyable }
        end

        def manual_lines
          counts.reject { |model, _count| destroyable?(model) }
                .map do |model, count|
                  "#{model.name}: #{count_label(count)} records need manual cleanup, " \
                    "see #{error_type.docs}."
                end
        end

        def count_label(count)
          "#{count}#{'+' if count >= COUNT_LIMIT}"
        end

        # Uploads are covered exactly once, but which table carries that coverage changes with
        # the partition rollout: https://gitlab.com/groups/gitlab-org/-/work_items/20933 and
        # https://gitlab.com/gitlab-org/gitlab/-/work_items/589924.
        #
        # While the parent Upload replicator owns verification, upload_states is the single
        # complete source for every partition and the per-partition *_upload_states tables are
        # only dual-written, so the partition models collapse into ::Upload. Once the parent
        # replicator is switched off, upload_states stops receiving verification failures and
        # each partition state table has to be read directly - collapsing then would query a
        # table nothing writes to any more and report zero for genuinely broken uploads.
        def model_classes
          models = verification_enabled_blob_models

          if ::Geo::UploadReplicator.verification_enabled?
            models = models.reject { |model| model <= ::Upload }
            models.unshift(::Upload)
          end

          models.select { |model| verification_state_class(model) }
        end

        # Blob replicables only: this error is about a file missing from storage. Verification
        # enablement is the right gate rather than replication enablement, because a replication
        # feature flag should not change what the cleanup tool reports.
        def verification_enabled_blob_models
          Gitlab::Geo.verification_enabled_replicator_classes
            .select { |replicator| replicator.ancestors.include?(::Geo::BlobReplicatorStrategy) }
            .map(&:model)
            .uniq
        end

        def verification_state_class(model)
          state_class = model.verification_state_table_class

          # Defensive: every blob replicable stores verification state in a Geo::*State table that
          # carries the model id in a column we can page by. An invariant spec asserts both hold
          # for every verification-enabled blob replicable, so a new one that breaks either fails
          # CI rather than quietly disappearing from the report.
          return unless state_class.respond_to?(:with_verification_failure_matching)
          return unless state_class.column_names.include?(model_id_column(model))

          state_class
        end

        # The state column holding the model id. NOT the state table's primary key: six blob state
        # tables (packages_package_file_states and friends) have their own surrogate `id` primary
        # key, so paging by the primary key there would yield state row ids and destroy unrelated
        # records. verification_state_model_key is overridden on exactly those models for this
        # reason.
        def model_id_column(model)
          model.verification_state_model_key.to_s
        end

        # Pages the matching state rows by the model id, yielding one batch of ids at a time.
        #
        # A cursor is needed rather than repeatedly reading the first page: records whose file
        # turns out to still be present are skipped rather than destroyed, so they stay in the
        # matching set and would otherwise be read forever.
        def each_matching_batch(model)
          state_class = verification_state_class(model)
          key = model_id_column(model)
          cursor = nil

          loop do
            ids = matching(state_class.after_cursor(cursor, key))
              .order(key => :asc)
              .limit(BATCH_SIZE)
              .pluck(key)

            break if ids.empty?

            cursor = ids.last

            yield ids
          end
        end

        # remaining caps how many records this batch may destroy, not how many it may check: a
        # candidate whose file is still present is skipped, so it must not eat into the budget.
        #
        # So LIMIT bounds the damage, not the runtime. A run with LIMIT=100 against a matching set
        # whose files mostly turn out to be present still walks the whole set, one storage check
        # (a HEAD request, for object storage) per record.
        def destroy_records(model, ids, remaining)
          destroyed_ids = []

          model.id_in(ids).each do |record|
            break if remaining && destroyed_ids.size >= remaining
            next unless file_missing?(record)

            # Dumped before the destroy, so a row that fails to destroy leaves a harmless extra
            # line rather than a destroyed row with no way back.
            write_recovery_dump(record)

            record.destroy!
            destroyed_ids << record.id
          rescue StandardError => e
            # Keep going: one record we cannot destroy (for example an upload whose owning model
            # is also gone, which belongs to the orphaned_uploads entry) must not abort the run.
            @failed_count += 1

            log(
              "Could not destroy replicable with a missing file",
              replicable_model: model.name,
              model_record_id: record.id,
              error_message: e.message
            )
          end

          if destroyed_ids.any?
            # Log the count and id range rather than the full id list: a real run can destroy up
            # to BATCH_SIZE records per batch, and dumping every id bloats the Geo log.
            log(
              "Destroyed replicables with missing files",
              replicable_model: model.name,
              count: destroyed_ids.size,
              min_record_id: destroyed_ids.min,
              max_record_id: destroyed_ids.max
            )
          end

          destroyed_ids.size
        end

        # The dump is the operator's undo: every row this destroys is otherwise only recoverable
        # from a backup. Mode 0600 because upload attributes include `secret`.
        #
        # sync so each line reaches the OS as it is written, rather than sitting in Ruby's buffer
        # while the row it describes is already destroyed. Without it a SIGKILL or OOM-kill loses
        # the buffered tail, which is the one situation this file exists for. It is a write(2) per
        # row, not an fsync, so it costs nothing next to the storage check and DELETE we already do
        # per row. Kernel or power failure can still lose the page cache.
        def open_recovery_dump
          check_recovery_dump_dir!

          path = recovery_dump_path
          @dumped_count = 0

          File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
            file.sync = true

            @recovery_dump = file
            @recovery_dump_path = path

            yield
          end

          return unless @dumped_count == 0

          # Every candidate was skipped, so the dump has nothing to restore. Remove it rather than
          # leave an empty file behind, and stop summary naming a path that no longer exists.
          File.unlink(path)
          @recovery_dump_path = nil
        ensure
          @recovery_dump = nil
        end

        # Checked before anything is destroyed, so an unwritable directory is a clear message rather
        # than a raw Errno from the middle of a run. Rails.root/tmp is fine on Omnibus but can be
        # read-only in a container, hence the override.
        def check_recovery_dump_dir!
          dir = recovery_dump_dir

          return if File.directory?(dir) && File.writable?(dir)

          raise "Cannot write the recovery dump to #{dir}. Nothing was destroyed. " \
            "Set RECOVERY_DUMP_DIR to a writable path and re-run."
        end

        # Random suffix so EXCL can stay: it guarantees we never append to or clobber an earlier
        # dump, which a timestamp alone cannot promise for two runs within the same second.
        def recovery_dump_path
          timestamp = Time.current.utc.strftime('%Y%m%dT%H%M%SZ')
          suffix = SecureRandom.hex(4)

          File.join(recovery_dump_dir, "geo-#{error_type.name}-destroyed-#{timestamp}-#{suffix}.jsonl")
        end

        def recovery_dump_dir
          options[:recovery_dump_dir].presence || Rails.root.join('tmp').to_s
        end

        def write_recovery_dump(record)
          return unless @recovery_dump

          @recovery_dump.puts(
            ::Gitlab::Json.dump(model: record.class.name, attributes: record.attributes)
          )

          @dumped_count += 1
        end

        # Storage has the last word: the failure text says the file was gone when verification
        # ran, and this confirms it is still gone now. Reuses the predicate verification itself
        # uses, so "missing" means here what it meant when the failure was recorded. Anything
        # else is left alone and counted as skipped, including the case where we cannot reach
        # storage, because then we cannot prove the file is missing.
        def file_missing?(record)
          missing = !record.replicator.resource_exists?
          @skipped_count += 1 unless missing

          missing
        rescue StandardError => e
          @skipped_count += 1

          log(
            "Could not check storage for a replicable with a failed verification",
            replicable_model: record.class.name,
            model_record_id: record.id,
            error_message: e.message
          )

          false
        end
      end
    end
  end
end
