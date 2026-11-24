# frozen_string_literal: true

module Gitlab
  module Cleanup
    # Finds package directories on local storage that belong to a deleted project,
    # and moves them to a lost and found directory. Files are never deleted.
    class OrphanPackageFiles
      include Gitlab::Utils::StrongMemoize

      BATCH_SIZE = 1_000
      # Directories with a file changed more recently are left for a later run
      MIN_AGE = 24.hours
      # Matches the `<aa>/<bb>/<sha256>` top level directories built by Gitlab::HashedPath
      HASHED_DIR_REGEX = %r{\A(\h{2})/(\h{2})/\1\2\h{60}\z}

      attr_reader :logger

      def initialize(logger: nil)
        @logger = logger || Gitlab::AppLogger
      end

      # @param dry_run [Boolean] when true, only report the orphaned directories
      # @return [void]
      def run!(dry_run: true)
        logger.info "Looking for orphaned package files to clean up#{'. Dry run' if dry_run}..."

        unless File.directory?(packages_root)
          logger.info "Packages storage path #{packages_root} does not exist. Nothing to do."
          return
        end

        count = 0
        failed = 0
        total_size = 0

        each_orphan_dir do |path, relative_path|
          status, size = clean_orphan_dir(path, relative_path, dry_run)

          case status
          when :moved
            count += 1
            total_size += size
          when :failed
            failed += 1
          end
        end

        verb = dry_run ? 'Found' : 'Moved'
        logger.info "#{verb} #{count} orphaned package directories, total size #{human_size(total_size)}"
        logger.error "#{failed} orphaned package directories cannot be moved. See the errors above." if failed > 0

        nil
      end

      private

      def packages_root
        File.absolute_path(::Packages::PackageFileUploader.root)
      end
      strong_memoize_attr :packages_root

      def lost_and_found
        File.join(packages_root, '-', 'package-lost-found')
      end

      # The disk is scanned before the database is read: a directory on disk means its
      # project existed when its files were written, and a deleted project never returns.
      # rubocop: disable CodeReuse/ActiveRecord -- reads IDs of two unrelated models
      def each_orphan_dir
        on_disk = each_candidate_dir.to_set { |_path, relative_path| relative_path }
        return if on_disk.empty?

        ::Project.each_batch(of: BATCH_SIZE) do |batch|
          cross_off(on_disk, batch.pluck_primary_key)
        end

        # Group Debian files share the hashed directory of the project with the same ID
        ::Packages::Debian::GroupDistribution.each_batch(of: BATCH_SIZE) do |batch|
          cross_off(on_disk, batch.distinct.pluck(:group_id))
        end

        on_disk.each { |relative_path| yield(File.join(packages_root, relative_path), relative_path) }
      end
      # rubocop: enable CodeReuse/ActiveRecord

      def cross_off(on_disk, root_hash_ids)
        # Without sub paths, HashedPath ends with a trailing slash
        on_disk.subtract(root_hash_ids.map { |id| Gitlab::HashedPath.new(root_hash: id).to_s.delete_suffix('/') })
      end

      def each_candidate_dir
        return to_enum(__method__) unless block_given?

        Open3.popen3(*find_command) do |_stdin, stdout, stderr, status_thread|
          # Drained concurrently: a full stderr pipe would block `find` while stdout is read
          stderr_reader = Thread.new { stderr.read }

          stdout.each_line do |line|
            path = line.chomp
            relative_path = path.delete_prefix("#{packages_root}/")

            # Skips non hashed directories such as `tmp` or the lost and found directory
            yield(path, relative_path) if HASHED_DIR_REGEX.match?(relative_path)
          end

          status = status_thread.value
          unless status.success?
            logger.error "find exited with status #{status.exitstatus}, the scan is incomplete: " \
              "#{stderr_reader.value.strip}"
          end
        end
      end

      def find_command
        # -H follows a symlinked storage root, but not symlinks below it
        %W[find -H #{packages_root} -mindepth 3 -maxdepth 3 -type d]
      end

      # @return [Array(Symbol, Integer)] `:moved`, `:skipped` or `:failed`, and the size of the directory
      def clean_orphan_dir(path, relative_path, dry_run)
        new_path = File.join(lost_and_found, relative_path)
        action = "move to lost and found #{path} -> #{new_path}"

        size, last_modified_at = dir_stats(path)

        if last_modified_at > MIN_AGE.ago
          logger.info "Skipping #{path}: changed in the last #{MIN_AGE.inspect}"
          return [:skipped, size]
        end

        if File.exist?(new_path)
          logger.error "Cannot #{action}: destination already exists"
          return [:failed, size]
        end

        if dry_run
          logger.info "Can #{action} (#{human_size(size)})"
          return [:moved, size]
        end

        FileUtils.mkdir_p(File.dirname(new_path))
        FileUtils.mv(path, new_path)

        logger.info "Did #{action} (#{human_size(size)})"
        [:moved, size]
      rescue StandardError => e
        logger.error "Error during #{action}: #{e.inspect}"
        [:failed, 0]
      end

      # @return [Array(Integer, Time)] the total size of the files and the latest modification time in the tree
      def dir_stats(path)
        size = 0
        last_modified_at = File.mtime(path)

        Dir.glob(File.join(path, '**', '*'), File::FNM_DOTMATCH) do |entry|
          stat = File.lstat(entry)
          size += stat.size if stat.file?
          last_modified_at = [last_modified_at, stat.mtime].max
        end

        [size, last_modified_at]
      end

      def human_size(bytes)
        ActiveSupport::NumberHelper.number_to_human_size(bytes)
      end
    end
  end
end
