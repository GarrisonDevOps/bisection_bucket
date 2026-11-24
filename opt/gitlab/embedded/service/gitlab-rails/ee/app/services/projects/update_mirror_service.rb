# frozen_string_literal: true

module Projects
  class UpdateMirrorService < BaseService
    include Gitlab::Utils::StrongMemoize

    Error = Class.new(StandardError)
    UpdateError = Class.new(Error)

    # WARNING: Changing GITALY_CONTEXT_KEY can cause undesirable side effects
    # during a GitLab upgrade, such as unwanted CI pipelines.
    GITALY_CONTEXT_KEY = 'pull-mirror-update'
    ASYNC_BRANCH_BATCH_SIZE = 20
    ASYNC_BRANCH_BATCH_DELAY = 30.seconds
    ASYNC_BRANCH_THRESHOLD = 100
    MAXIMUM_ASYNC_BRANCHES = 1000

    def execute
      validate_import_url!

      unless can?(current_user, :access_git)
        return error('The mirror user is not allowed to perform any git operations.')
      end

      return success unless project.mirror?

      # This should be an error, but to prevent the mirroring
      # from being disabled when moving between shards
      # we make it "success" for time being
      # Ref: https://gitlab.com/gitlab-org/gitlab/merge_requests/19182
      return success if project.repository_read_only?

      unless can?(current_user, :push_code_to_protected_branches, project)
        return error("The mirror user is not allowed to push code to all branches on this project.")
      end

      update_branches_result = {}
      track_pull_mirror_update_across_post_receive do
        fetch_result = update_tags do
          project.fetch_mirror(forced: true, resolved_address: resolved_address)
        end

        update_branches_result = update_lfs_objects_and_branches(fetch_result)

        # Running git fetch in the repository creates loose objects in the same
        # way running git push *to* the repository does, so ensure we run regular
        # garbage collection
        run_housekeeping
      end

      update_branches_result[:async] ? success(async: true) : success
    rescue Gitlab::HTTP_V2::UrlBlocker::BlockedUrlError => e
      error("The import URL is invalid: #{e.message}")
    rescue Gitlab::Shell::Error, Gitlab::Git::BaseError, UpdateError => e
      error(e.message)
    end

    def update_lfs_objects_and_branches(fetch_result)
      update_lfs_objects if fetch_result.repo_changed

      update_branches
    end

    private

    def track_pull_mirror_update_across_post_receive(&block)
      # Set a context flag that will be preserved across the post-receive
      # boundary. This allows us to identify mirror-triggered operations later.
      # For example in the pipeline validation chain, preventing unwanted CI
      # pipelines when the project setting `mirror_trigger_builds` is `false`
      ::Gitlab::GitalyClient.with_context(GITALY_CONTEXT_KEY => true, &block)
    end

    def update_lfs_objects
      return unless project.lfs_enabled?

      updated_revisions = branch_changes_calculator.calculate_changed_revisions
      return if updated_revisions.nil?

      result = Projects::LfsPointers::LfsImportService.new(project, current_user, { updated_revisions: updated_revisions }).execute

      if result[:status] == :error
        Gitlab::Metrics::Lfs.update_objects_error_rate.increment(error: true, labels: {})
        log_error(result[:message])
        # Uncomment once https://gitlab.com/gitlab-org/gitlab-foss/issues/61834 is closed
        # raise UpdateError, result[:message]
      else
        Gitlab::Metrics::Lfs.update_objects_error_rate.increment(error: false, labels: {})
      end
    end

    # Validates the import URL and memoizes the result.
    # Returns [validated_url, resolved_host] or nil if URL is blank.
    # Raises BlockedUrlError if URL is blocked.
    #
    strong_memoize_attr def validated_url_result
      return unless project.unsafe_import_url

      Gitlab::HTTP_V2::UrlBlocker.validate!(
        normalized_url(project.unsafe_import_url),
        schemes: Project::VALID_MIRROR_PROTOCOLS,
        allow_localhost: allow_local_requests?,
        allow_local_network: allow_local_requests?,
        dns_rebind_protection: dns_rebind_protection?,
        deny_all_requests_except_allowed: Gitlab::CurrentSettings.deny_all_requests_except_allowed?,
        outbound_local_requests_allowlist: Gitlab::CurrentSettings.outbound_local_requests_whitelist) # rubocop:disable Naming/InclusiveLanguage -- existing setting
    end

    def validate_import_url!
      validated_url_result # raises BlockedUrlError if blocked
    end

    # Returns the resolved IP address for HTTP/HTTPS/Git URLs to prevent DNS rebinding attacks.
    # For SSH URLs or when resolved_host is nil, returns an empty string.
    #
    # Note: SSH URLs don't need DNS rebinding protection because SSH connections
    # verify the host key, which is tied to the server's identity.
    #
    def resolved_address
      result = validated_url_result
      return '' unless result

      import_url, resolved_host = result
      return '' if resolved_host.nil? || !import_url.scheme.in?(%w[http https git])

      import_url.hostname.to_s
    end

    def allow_local_requests?
      Gitlab::CurrentSettings.allow_local_requests_from_web_hooks_and_services?
    end

    def dns_rebind_protection?
      return false if Gitlab.http_proxy_env?

      Gitlab::CurrentSettings.dns_rebinding_protection_enabled?
    end

    def normalized_url(url)
      strong_memoize_with(:normalized_url, url) do
        CGI.unescape(Gitlab::UrlSanitizer.sanitize(url))
      end
    end

    def update_branches
      local_branches = repository.branches.index_by(&:name)

      errors = []
      branches_to_create = {}

      repository.upstream_branches.each do |upstream_branch|
        name = upstream_branch.name

        next if skip_branch?(name)

        local_branch = local_branches[name]

        if local_branch.nil?
          branches_to_create[name] = upstream_branch.dereferenced_target.sha
        elsif local_branch.dereferenced_target == upstream_branch.dereferenced_target
          # Already up to date
        elsif repository.diverged_from_upstream?(name)
          handle_diverged_branch(upstream_branch, local_branch, name, errors)
        else
          begin
            repository.ff_merge(current_user, upstream_branch.dereferenced_target, name)
          rescue Gitlab::Git::PreReceiveError, Gitlab::Git::CommitError => e
            errors << e.message
          end
        end
      end

      service_logger.info(base_payload.merge(
        message: 'Mirror update creating branches',
        branches_count: branches_to_create.size
      ))

      create_branches(branches_to_create, errors)
    end

    def create_branches(branches_to_create, errors)
      # Prevent pipeline explosion on first sync by only allowing a pipeline
      # for the default branch. See https://gitlab.com/gitlab-org/gitlab/-/issues/598486
      if skip_ci_for_non_default_branches?
        create_default_branch_separately(branches_to_create, errors)
      end

      if branches_to_create.empty?
        raise UpdateError, errors.join("\n\n") unless errors.empty?

        return { status: :success }
      end

      entries = branches_to_create.to_a
      sync_branches = entries.first(ASYNC_BRANCH_THRESHOLD).to_h
      async_branches = entries.drop(ASYNC_BRANCH_THRESHOLD).to_h

      result = ::Branches::CreateService.new(project, current_user)
        .bulk_create(sync_branches, skip_ci: skip_ci_for_non_default_branches?)
      errors << result[:message] if result[:status] == :error

      if errors.empty? && async_branches.present?
        result[:async] = true
        create_branches_async(async_branches)
      end

      unless errors.empty?
        raise UpdateError, errors.join("\n\n")
      end

      result
    end

    # Creates the default branch without skip_ci so it gets a pipeline.
    # Removes the default branch from branches_to_create so it's not
    # processed again by bulk_create.
    #
    def create_default_branch_separately(branches_to_create, errors)
      default_branch_name = project.default_branch
      default_branch_ref = branches_to_create.delete(default_branch_name)

      return unless default_branch_ref

      result = ::Branches::CreateService.new(project, current_user)
        .execute(default_branch_name, default_branch_ref, create_default_branch_if_empty: false)
      errors << result[:message] if result[:status] == :error
    end

    def create_branches_async(branches)
      schedulable, excess_count = cap_async_branches(branches)

      waiter = Gitlab::JobWaiter.new
      jobs_remaining = schedule_async_batches(schedulable, waiter.key)

      ::Repositories::CreateBranchesFinishWorker.perform_async(
        project.id, waiter.key, jobs_remaining, excess_count
      )
    end

    def cap_async_branches(branches)
      excess = [branches.size - MAXIMUM_ASYNC_BRANCHES, 0].max
      [branches.first(MAXIMUM_ASYNC_BRANCHES).to_h, excess]
    end

    def schedule_async_batches(branches, waiter_key)
      skip_ci = skip_ci_for_non_default_branches?

      branches.each_slice(ASYNC_BRANCH_BATCH_SIZE).with_index.sum do |batch, index|
        objects = batch.map { |name, ref| [name, ref] }

        ::Repositories::CreateBranchWorker.bulk_perform_in_with_contexts(
          batch_delay_for(index),
          objects,
          arguments_proc: ->((name, ref)) { [project.id, current_user.id, name, ref, waiter_key, skip_ci] },
          context_proc: ->(_) { { project: project } }
        )

        batch.size
      end
    end

    def batch_delay_for(index)
      # +1 because bulk_perform_in requires a strictly future time
      (index * ASYNC_BRANCH_BATCH_DELAY) + 1.second
    end

    def update_tags(&block)
      old_tags = repository_tags_with_target.index_by(&:name)

      fetch_result = yield
      return fetch_result unless fetch_result&.tags_changed

      repository.expire_tags_cache

      tags = repository_tags_with_target

      tags_to_remove = []

      tags.each do |tag|
        old_tag = old_tags[tag.name]
        tag_target = tag.dereferenced_target.sha
        old_tag_target = old_tag ? old_tag.dereferenced_target.sha : repository.blank_ref

        next if old_tag_target == tag_target

        unless can_create_tag?(tag)
          tags_to_remove << tag
          next
        end

        change = { oldrev: old_tag_target, newrev: tag_target, ref: tag_reference(tag) }

        Git::TagPushService.new(
          project,
          current_user,
          change: change,
          mirror_update: true,
          create_pipelines: !skip_ci_for_tags?
        ).execute
      end

      if tags_to_remove.present?
        refs = tags_to_remove.map { |tag| tag_reference(tag) }

        project.repository.delete_refs(*refs)
        project.repository.expire_tags_cache

        # Only take 10 tags to keep the error message short
        not_allowed_tags = tags_to_remove.first(10).map { |tag| "'#{tag.name}'" }
        not_allowed_tags << 'and others' if tags_to_remove.count > 10

        raise UpdateError, "You are not allowed to create tags: #{not_allowed_tags.join(', ')} as they are protected."
      end

      fetch_result
    end

    def can_create_tag?(tag)
      ::Gitlab::UserAccess.new(current_user, container: project).can_create_tag?(tag.name)
    end

    def tag_reference(tag)
      "#{Gitlab::Git::TAG_REF_PREFIX}#{tag.name}"
    end

    def handle_diverged_branch(upstream, local, branch_name, errors)
      if project.mirror_overwrites_diverged_branches?
        newrev = upstream.dereferenced_target.sha
        oldrev = local.dereferenced_target.sha

        # If the user doesn't have permission to update the diverged branch
        # (e.g. it's protected and the user can't force-push to protected
        # branches), this will fail.
        repository.update_branch(branch_name, user: current_user, newrev: newrev, oldrev: oldrev)
      elsif branch_name == project.default_branch
        # Cannot be updated
        errors << "The default branch (#{project.default_branch}) has diverged from its upstream counterpart and could not be updated automatically."
      else
        # We ignore diverged branches other than the default branch
      end
    end

    def run_housekeeping
      service = ::Repositories::HousekeepingService.new(project)

      service.increment!
      service.execute if service.needed?
    rescue ::Repositories::HousekeepingService::LeaseTaken
      # best-effort
    end

    # In Git is possible to tag blob objects, and those blob objects don't point to a Git commit so those tags
    # have no target.
    def repository_tags_with_target
      repository.tags.select(&:dereferenced_target)
    end

    def skip_branch?(name)
      branch_filter.skip_branch?(name)
    end

    def branch_filter
      @branch_filter ||= Gitlab::Repositories::Mirror::BranchSkipFilter.new(project)
    end

    def branch_changes_calculator
      @branch_changes_calculator ||= Gitlab::Repositories::Mirror::LocalRemoteBranchComparator.new(project, branch_filter: branch_filter)
    end

    def service_logger
      @service_logger ||= Gitlab::UpdateMirrorServiceJsonLogger.build
    end

    def base_payload
      {
        user_id: current_user.id,
        project_id: project.id,
        import_url: project.safe_import_url
      }
    end

    def log_error(error_message)
      service_logger.error(base_payload.merge(error_message: error_message))
    end

    # Detected via import_state#ever_updated_successfully? which is set after
    # the first successful mirror sync completes.
    def first_sync?
      !project.import_state&.ever_updated_successfully?
    end
    strong_memoize_attr :first_sync?

    # Only on first sync. The default branch is handled separately and will
    # get a pipeline.
    def skip_ci_for_non_default_branches?
      first_sync?
    end

    # On first sync, skip pipelines for ALL tags (there's no "default" tag).
    def skip_ci_for_tags?
      skip_ci_for_non_default_branches?
    end
  end
end
