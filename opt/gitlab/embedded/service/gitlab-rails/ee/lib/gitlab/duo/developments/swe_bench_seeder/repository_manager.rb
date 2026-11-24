# frozen_string_literal: true

module Gitlab
  module Duo
    module Developments
      class SweBenchSeeder
        class RepositoryManager
          MIRRORS_SUBGROUP_PATH = 'mirrors'
          MAX_CLONE_RETRIES = 3

          # Top-level entry point called from the seeder for all examples at once.
          #
          # Strategy:
          # 1. Clone each unique repo once into mirrors/ (sequential, network-bound).
          # 2. Fire all forks in parallel (no waiting between them).
          # 3. Wait with a single polling loop across all pending forks (1 DB query per tick).
          # 4. strip_to_commit on each finished fork.
          #
          # Returns a hash of instance_id => project (nil for failures).
          def self.setup_instance_projects(examples, subgroup, user)
            mirrors_group = find_or_create_mirrors_group(subgroup, user)
            return {} unless mirrors_group

            mirrors = ensure_mirrors(examples, mirrors_group, subgroup, user)

            enqueue_clones(examples, mirrors, subgroup, user)
          end

          # Clone each unique upstream repo once. Sequential because each clone is
          # network-bound -- parallelising them would just saturate the connection.
          def self.ensure_mirrors(examples, mirrors_group, subgroup, user)
            mirrors = {}
            repos = examples.map { |e| e['inputs']['repo'] }.uniq
            total = repos.size

            repos.each_with_index do |repo, index|
              puts "\n[mirror #{index + 1}/#{total}] #{repo}"
              mirror = ensure_mirror(
                "#{Config.source_base_url}/#{repo}.git",
                repo, mirrors_group, subgroup, user
              )

              raise "Mirror creation failed for #{repo}. Cannot continue seeding." unless mirror&.persisted?

              mirrors[repo] = mirror
            end

            mirrors
          end

          # Enqueue all instance clones immediately without waiting, then wait for
          # all of them with one shared polling loop. Retries zombie/failed clones
          # up to MAX_CLONE_RETRIES times before giving up.
          def self.enqueue_clones(examples, mirrors, subgroup, user)
            pending = {}
            total = examples.size

            examples.each_with_index do |example, index|
              inputs = example['inputs']
              instance_id = inputs['instance_id']
              repo = inputs['repo']
              base_commit = inputs['base_commit']

              mirror = mirrors[repo]
              unless mirror
                puts "  [#{index + 1}/#{total}] #{instance_id}: skipped (no mirror for #{repo})"
                next
              end

              project = start_clone_from_mirror(mirror, instance_id, subgroup, user, index + 1, total)
              next unless project

              pending[instance_id] = { project: project, base_commit: base_commit }
            end

            all_results = {}

            (1..MAX_CLONE_RETRIES).each do |attempt|
              if attempt > 1
                puts "\nRetrying #{pending.size} failed clone(s) (attempt #{attempt}/#{MAX_CLONE_RETRIES})..."
                pending = reenqueue_clones(pending, examples, mirrors, subgroup, user)
              end

              puts "\nWaiting for #{pending.size}/#{total} clone(s) to complete..."
              results = wait_for_all_imports(pending, user, total: total)
              all_results.merge!(results)

              failed_ids = pending.keys - results.keys
              break if failed_ids.empty?

              if attempt == MAX_CLONE_RETRIES
                raise "#{failed_ids.size} clone(s) failed after #{MAX_CLONE_RETRIES} attempts: " \
                  "#{failed_ids.join(', ')}. Cannot continue seeding."
              end

              puts "\n#{failed_ids.size} clone(s) failed (zombie/dropped), will retry: #{failed_ids.join(', ')}"
              pending = pending.slice(*failed_ids)
            end

            all_results
          end

          # Re-enqueue failed clones by destroying the old project and starting fresh.
          def self.reenqueue_clones(pending, examples, mirrors, subgroup, user)
            new_pending = {}
            example_map = examples.index_by { |e| e['inputs']['instance_id'] }
            count = pending.size

            pending.each.with_index do |(instance_id, _entry), index|
              example = example_map[instance_id]
              repo = example['inputs']['repo']
              mirror = mirrors[repo]
              base_commit = example['inputs']['base_commit']

              project = start_clone_from_mirror(mirror, instance_id, subgroup, user, index + 1, count)
              next unless project

              new_pending[instance_id] = { project: project, base_commit: base_commit }
            end

            new_pending
          end

          # Enqueue a clone of the local mirror and return the project immediately.
          # Using import_url pointing at the local mirror avoids GitHub traffic after
          # the mirror is created, and sidesteps fork_network complexity entirely.
          def self.start_clone_from_mirror(mirror, instance_id, subgroup, user, index, total)
            project_name = instance_id_to_project_name(instance_id)
            project_full_path = "#{subgroup.full_path}/#{project_name}"

            existing = Project.find_by_full_path(project_full_path)
            if existing
              # Synchronous destroy so the path is free immediately for the new import.
              ::Projects::DestroyService.new(existing, user).execute # rubocop:disable Gitlab/HardDeleteCalls -- Dev-only seeder
            end

            # Build the local HTTP clone URL for the mirror using the GDK base URL.
            mirror_clone_url = "#{Config.seed_base_url}/#{mirror.full_path}.git"

            project = ::Projects::CreateService.new(user, {
              name: project_name,
              path: project_name,
              namespace_id: subgroup.id,
              import_url: mirror_clone_url,
              visibility_level: subgroup.visibility_level,
              import_data: {
                data: { timeout_strategy: 'optimistic' },
                optional_stages: {
                  attachments_import: false,
                  collaborators_import: false
                }
              }
            }).execute

            if project.errors.any?
              puts "  [#{index}/#{total}] #{instance_id}: clone failed --#{project.errors.full_messages.join(', ')}"
              return
            end

            puts "  [#{index}/#{total}] #{instance_id}: clone enqueued"
            project
          rescue StandardError => e
            puts "  [#{index}/#{total}] #{instance_id}: error enqueuing clone --#{e.message}"
            nil
          end

          # Poll all pending imports with a single DB query per tick.
          # On completion, strip each project to its base_commit.
          # Returns instance_id => project for all successfully finished projects.
          #
          # rubocop:disable Metrics/AbcSize, CodeReuse/ActiveRecord -- Dev-only seeder, direct DB queries are intentional
          def self.wait_for_all_imports(
            pending, user, total:, max_wait_seconds: 600,
            poll_interval: 3, zombie_threshold_seconds: 120)
            start_time = Time.current
            results = {}
            done = 0

            project_ids = pending.values.map { |v| v[:project].id }
            id_to_instance = pending.transform_values { |v| v[:project].id }.invert

            until project_ids.empty?
              elapsed = Time.current - start_time

              if elapsed > max_wait_seconds
                pending_names = project_ids.map { |id| id_to_instance[id] }.join(', ')
                puts "Timeout waiting for #{project_ids.size} import(s): #{pending_names}"
                break
              end

              terminal = ProjectImportState
                .where(project_id: project_ids, status: %w[finished failed canceled])
                .pluck(:project_id, :status, :last_error)

              terminal.each do |project_id, status, last_error|
                instance_id = id_to_instance[project_id]
                entry = pending[instance_id]
                project_ids.delete(project_id)
                done += 1

                if status == 'finished'
                  project = entry[:project].reset
                  strip_to_commit(project, entry[:base_commit], user)
                  results[instance_id] = project
                  puts "  [#{done}/#{total}] #{instance_id}: done (#{elapsed.round(1)}s)"
                else
                  puts "  [#{done}/#{total}] #{instance_id}: import #{status} --#{last_error}"
                end
              rescue StandardError => e
                puts "  [#{done}/#{total}] #{instance_id}: FAILED --#{e.message}"
              end

              # Detect zombie jobs: started long ago but repo is still empty.
              # Sidekiq can silently drop jobs (OOM, worker restart) leaving status='started' forever.
              if project_ids.any?
                zombie_states = ProjectImportState
                  .where(project_id: project_ids, status: 'started')
                  .where(last_update_started_at: ...zombie_threshold_seconds.seconds.ago)
                  .pluck(:project_id)

                zombie_states.each do |project_id|
                  instance_id = id_to_instance[project_id]
                  entry = pending[instance_id]
                  next if entry[:project].repository.exists?

                  project_ids.delete(project_id)
                  done += 1
                  puts "  [#{done}/#{total}] #{instance_id}: ZOMBIE (repo empty after #{zombie_threshold_seconds}s)"
                end
              end

              unless project_ids.empty?
                puts "  [#{done}/#{total} done, #{project_ids.size} pending] #{elapsed.round(1)}s elapsed..."
                sleep poll_interval
              end
            end

            results
          end
          # rubocop:enable Metrics/AbcSize, CodeReuse/ActiveRecord

          def self.ensure_mirror(repository_url, repo, mirrors_group, subgroup, user)
            mirror_name = repo.split('/').last
            mirror_full_path = "#{mirrors_group.full_path}/#{mirror_name}"
            existing = Project.find_by_full_path(mirror_full_path)

            if existing
              if existing.repository.exists? && existing.repository.commit
                puts "Mirror already exists: #{mirror_full_path}"
                return existing
              end

              puts "Mirror exists but repository is empty/broken, re-creating: #{mirror_full_path}"
              ::Projects::DestroyService.new(existing, user).execute # rubocop:disable Gitlab/HardDeleteCalls -- Dev-only seeder
            end

            puts "\nCloning mirror from #{repository_url}..."

            project_params = {
              name: mirror_name,
              path: mirror_name,
              namespace_id: mirrors_group.id,
              import_url: repository_url,
              visibility_level: subgroup.visibility_level,
              import_data: {
                data: { timeout_strategy: 'optimistic' },
                optional_stages: {
                  attachments_import: false,
                  collaborators_import: false
                }
              }
            }

            project = ::Projects::CreateService.new(user, project_params).execute

            if project.errors.any?
              puts "Failed to create mirror: #{project.errors.full_messages.join(', ')}"
              return
            end

            puts "Created mirror: #{project.full_path}"
            return unless wait_for_single_import(project)

            project
          rescue StandardError => e
            puts "Error creating mirror: #{e.message}"
            puts e.backtrace.first(5).join("\n")
            nil
          end

          def self.instance_id_to_project_name(instance_id)
            instance_id.gsub('__', '-').tr('_', '-')
          end

          def self.find_or_create_mirrors_group(subgroup, user)
            mirrors_full_path = "#{subgroup.full_path}/#{MIRRORS_SUBGROUP_PATH}"
            existing = Group.find_by_full_path(mirrors_full_path)
            return existing if existing

            response = Groups::CreateService.new(user, {
              name: MIRRORS_SUBGROUP_PATH,
              path: MIRRORS_SUBGROUP_PATH,
              parent_id: subgroup.id,
              organization: subgroup.organization,
              visibility_level: subgroup.visibility_level
            }).execute

            if response.error?
              puts "Failed to create mirrors group: #{response.message}"
              return
            end

            response[:group]
          rescue StandardError => e
            puts "Error creating mirrors group: #{e.message}"
            nil
          end

          # Single-project blocking wait -- used only for mirrors.
          # rubocop:disable CodeReuse/ActiveRecord -- Dev-only seeder
          def self.wait_for_single_import(project, max_wait_seconds: 600, poll_interval: 2)
            start_time = Time.current

            loop do
              elapsed = Time.current - start_time
              return false if elapsed > max_wait_seconds

              state = ProjectImportState.find_by(project_id: project.id)
              puts "  Waiting... #{elapsed.round(1)}s [#{state&.status}]"

              return true  if state&.finished?
              return false if state&.failed? || state&.canceled?

              sleep poll_interval
            end
          rescue StandardError => e
            puts "Error waiting for mirror import: #{e.message}"
            false
          end
          # rubocop:enable CodeReuse/ActiveRecord

          def self.strip_to_commit(project, commit_sha, _user)
            # Expire caches before any read -- the project object may have been loaded
            # before the import completed, leaving stale (empty) repository state cached.
            project.repository.expire_all_method_caches

            default_branch = project.repository.root_ref || project.default_branch_or_main

            # Fail fast if the SHA doesn't exist -- better than a cryptic Gitaly error later.
            verify_commit_exists!(project, commit_sha)

            # Delete all branches except the default branch so the agent cannot
            # discover future commits or unrelated work via branch listing.
            branches_to_delete = project.repository.branch_names.reject { |b| b == default_branch }
            if branches_to_delete.any?
              refs = branches_to_delete.map { |b| "#{Gitlab::Git::BRANCH_REF_PREFIX}#{b}" }
              project.repository.delete_refs(*refs)
            end

            # Delete all tags -- they expose commit SHAs the agent shouldn't know about.
            tag_names = project.repository.tag_names
            if tag_names.any?
              tag_refs = tag_names.map { |t| "#{Gitlab::Git::TAG_REF_PREFIX}#{t}" }
              project.repository.delete_refs(*tag_refs)
            end

            # Force-reset the default branch to exactly base_commit using write_ref
            # (not update_branch which requires oldrev and does a non-force update).
            # History behind base_commit stays intact so the agent can read the codebase,
            # but no commits after base_commit are reachable from any ref.
            project.repository.raw_repository.write_ref(default_branch, commit_sha)

            # Verify the strip actually worked -- seeding should fail loudly, not silently.
            verify_strip!(project, commit_sha, default_branch)
          rescue StandardError => e
            raise "strip_to_commit failed for #{project.full_path} @ #{commit_sha}: #{e.message}"
          end

          def self.verify_commit_exists!(project, commit_sha)
            return if project.repository.commit(commit_sha)

            raise "base_commit #{commit_sha} not found in #{project.full_path} --" \
              "mirror may be incomplete or SHA is wrong"
          end

          def self.verify_strip!(project, expected_sha, default_branch)
            project.repository.expire_all_method_caches

            actual_sha = project.repository.commit(default_branch)&.id
            raise "HEAD mismatch: expected #{expected_sha}, got #{actual_sha}" if actual_sha != expected_sha

            branch_count = project.repository.branch_names.count
            raise "Expected 1 branch, got #{branch_count}" if branch_count != 1

            tag_count = project.repository.tag_names.count
            raise "Expected 0 tags, got #{tag_count}" if tag_count != 0
          end
        end
      end
    end
  end
end
