# frozen_string_literal: true

module Gitlab
  module Duo
    module Developments
      # Mirrors the CEF `fix_pipeline_next` test catalog from production
      # (gitlab-org/duo-workflow/test-project-playground/duofixfailingpipelinecef
      # on gitlab.com) into local GDK. Five idempotent phases:
      #
      #   1. Locate the destination project (must already exist locally).
      #   2. Load the catalog from the LangSmith dataset.
      #   3. Synthesize CI records the file export dropped -- cross-pipeline `needs:` jobs, downstream child pipelines,
      #      parent->child link.
      #      These are read-only fixtures; nothing runs them.
      #   4. Replay prod job traces onto matching local jobs.
      #   5. Write `fix_pipeline_evaluation_pipelines.yml` (consumed via CEF_FIX_PIPELINE_URL_OVERRIDE_YAML) and verify
      #      completeness.
      #
      # The source project must be imported manually before running this task (export from gitlab.com via UI / `glab
      # project export`, then import locally). The mirror only fills in CI fixtures the file export format can't
      # represent.
      class CefFixPipelineMirror
        SOURCE_GITLAB_URL = 'https://gitlab.com'
        SOURCE_PROJECT_PATH = 'gitlab-org/duo-workflow/test-project-playground/duofixfailingpipelinecef'
        SOURCE_LANGSMITH_DATASET = 'cef.fix_pipeline.materialized.v1'
        DEFAULT_LANGSMITH_ENDPOINT = 'https://api.smith.langchain.com'

        DEFAULT_GROUP_PATH = 'gitlab-duo'
        DEFAULT_PROJECT_PATH = 'duofixfailingpipelinecef'

        RESET_DEADLINE_S = 30

        HTTP_RETRY_ATTEMPTS = 3
        HTTP_RETRY_BASE_DELAY_S = 1.5
        HTTP_RETRYABLE_STATUSES = [500, 502, 503, 504].freeze

        # @return [Boolean] true if every catalog row has a local pipeline with traces.
        def self.mirror(
          group_path: DEFAULT_GROUP_PATH,
          project_path: DEFAULT_PROJECT_PATH,
          output_file: 'fix_pipeline_evaluation_pipelines.yml'
        )
          gitlab_token = ENV['GITLAB_COM_AT']
          langchain_api_key = ENV['LANGCHAIN_API_KEY']
          preflight_checks!(gitlab_token, langchain_api_key, group_path, project_path)

          user = find_root_user
          full_path = "#{group_path}/#{project_path}"

          puts "[1/5] Locating destination project #{full_path} ..."
          imported = find_destination_project!(full_path)
          puts "    using #{imported.full_path} (id=#{imported.id})"

          puts '[2/5] Loading catalog from LangSmith ...'
          prod_rows = fetch_prod_manifest_from_langsmith(langchain_api_key)
          puts "    loaded #{prod_rows.size} rows from dataset '#{SOURCE_LANGSMITH_DATASET}'"

          puts '[3/5] Repairing missing CI records (jobs/downstream pipelines dropped by the file export) ...'
          repair_against_prod(prod_rows, imported, gitlab_token, user)

          puts '[4/5] Replaying job traces from gitlab.com ...'
          overrides = replay_traces(prod_rows, imported, gitlab_token)
          written_path = write_url_override_yaml(overrides, output_file)
          puts "    wrote #{overrides.size} URL overrides -> #{written_path}"

          puts '[5/5] Verifying completeness ...'
          ok = verify_completeness(prod_rows, imported)

          puts
          puts(ok ? 'Mirror complete. Local state matches production.' : 'Mirror finished with gaps. See report above.')
          ok
        end

        def self.preflight_checks!(gitlab_token, langchain_api_key, group_path, project_path)
          errors = []
          errors << 'GITLAB_COM_AT is not set' if gitlab_token.blank?
          errors << 'LANGCHAIN_API_KEY is not set' if langchain_api_key.blank?

          unless Namespace.find_by_full_path(group_path)
            errors << "Namespace '#{group_path}' not found (must be a group, not a user)"
          end

          full_path = "#{group_path}/#{project_path}"
          unless Project.find_by_full_path(full_path)
            errors << "Project '#{full_path}' not found locally. Import the source project export tarball " \
              "before running this task (see class docs)."
          end

          errors << probe_gitlab_com(gitlab_token) if gitlab_token.present?
          errors << probe_langsmith(langchain_api_key) if langchain_api_key.present?
          errors.compact!

          return if errors.empty?

          warn 'Pre-flight checks failed:'
          errors.each { |e| warn "  - #{e}" }
          abort 'Pre-flight checks failed; aborting before any local state is modified.'
        end
        private_class_method :preflight_checks!

        def self.probe_gitlab_com(token)
          gitlab_com_get("/api/v4/projects/#{CGI.escape(SOURCE_PROJECT_PATH)}", token)
          nil
        rescue StandardError => e
          "Cannot reach source project on gitlab.com: #{e.message}"
        end
        private_class_method :probe_gitlab_com

        def self.probe_langsmith(api_key)
          endpoint = ENV['LANGCHAIN_ENDPOINT'] || DEFAULT_LANGSMITH_ENDPOINT
          return if resolve_langsmith_dataset_id(endpoint, SOURCE_LANGSMITH_DATASET, api_key)

          "LangSmith dataset '#{SOURCE_LANGSMITH_DATASET}' not found at #{endpoint}"
        rescue StandardError => e
          "LangSmith probe failed: #{e.message}"
        end
        private_class_method :probe_langsmith

        def self.find_destination_project!(full_path)
          Project.find_by_full_path(full_path) ||
            abort("Error: no project at #{full_path}. Import the source project export tarball locally first.")
        end
        private_class_method :find_destination_project!

        # The file-based project export drops cross-job `needs:` deps and
        # downstream pipelines triggered by `trigger:` bridges. Synthesize
        # both from prod metadata so the agent's read-side tools see the
        # same shape as production. Nothing runs the synthesized records.
        def self.repair_against_prod(prod_rows, local_project, gitlab_token, user)
          prod_rows.each do |row|
            fp_id = row['fp_id']
            next unless eligible_row?(row, fp_id)

            prod_project_id, prod_pipeline_id = parse_pipeline_url(row['prod_pipeline_url'])
            next unless prod_project_id && prod_pipeline_id

            local_pipeline = find_local_pipeline(local_project, row['source_branch'])
            next unless local_pipeline

            repair_missing_jobs(local_pipeline, prod_project_id, prod_pipeline_id, gitlab_token, fp_id, user)
            repair_missing_downstream(local_pipeline, prod_project_id, prod_pipeline_id, gitlab_token, fp_id, user)
          end
        end
        private_class_method :repair_against_prod

        def self.repair_missing_jobs(local_pipeline, prod_project_id, prod_pipeline_id, token, fp_id, user)
          prod_jobs = fetch_jobs(prod_project_id, prod_pipeline_id, token)
          prod_jobs.each do |prod_job|
            next if local_pipeline.all_jobs.find_by_name(prod_job['name'])

            create_local_build_from_prod(local_pipeline, prod_job, user)
            puts "    [#{fp_id}] synthesized job '#{prod_job['name']}' (status=#{prod_job['status']})"
          end
        end
        private_class_method :repair_missing_jobs

        def self.repair_missing_downstream(local_parent, prod_project_id, prod_pipeline_id, token, fp_id, user)
          local_parent.bridges.each do |bridge|
            prod_child_id = fetch_downstream_pipeline_id(prod_project_id, prod_pipeline_id, bridge.name, token)
            next unless prod_child_id

            local_child = bridge.downstream_pipeline ||
              create_local_child_pipeline(prod_project_id, prod_child_id, local_parent, bridge, token, user)

            before = local_child.all_jobs.count
            repair_missing_jobs(local_child, prod_project_id, prod_child_id, token, "#{fp_id} (child)", user)
            after = local_child.reset.all_jobs.count

            next if before == after && bridge.downstream_pipeline

            puts "    [#{fp_id}] downstream pipeline #{local_child.id} for bridge '#{bridge.name}': " \
              "#{after} jobs (added #{after - before})"
          end
        end
        private_class_method :repair_missing_downstream

        # Synthesize a read-only Ci::Build fixture. `status=` + save!(validate: false)
        # deliberately bypass the state machine -- the build must never execute and must
        # persist directly in whatever status prod had. If a future Rails upgrade
        # intercepts `status=`, jobs will silently land in the wrong status
        # (verify_completeness catches "no trace" but not "wrong status").
        def self.create_local_build_from_prod(local_pipeline, prod_job, user)
          stage_name = prod_job['stage'].presence || 'test'
          stage_idx = prod_job['stage_idx'] || 0
          stage = find_or_create_local_stage(local_pipeline, stage_name, stage_idx)

          build = ::Ci::Build.new(
            pipeline: local_pipeline,
            project: local_pipeline.project,
            partition_id: local_pipeline.partition_id,
            name: prod_job['name'],
            ci_stage: stage,
            stage_idx: stage_idx,
            user: user,
            finished_at: prod_job['finished_at']
          )
          build.status = prod_job['status'].presence || 'failed'
          build.save!(validate: false)
          build
        end
        private_class_method :create_local_build_from_prod

        # rubocop:disable CodeReuse/ActiveRecord -- dev seeder; lookup by name is the natural form
        def self.find_or_create_local_stage(local_pipeline, stage_name, stage_idx)
          existing = local_pipeline.stages.find_by(name: stage_name)
          return existing if existing

          ::Ci::Stage.create!(
            pipeline: local_pipeline,
            project: local_pipeline.project,
            partition_id: local_pipeline.partition_id,
            name: stage_name,
            position: stage_idx,
            status: 'failed'
          )
        end
        # rubocop:enable CodeReuse/ActiveRecord
        private_class_method :find_or_create_local_stage

        # Synthesize a downstream Ci::Pipeline + its jobs + the parent->child
        # link record (Ci::Sources::Pipeline).
        def self.create_local_child_pipeline(prod_project_id, prod_child_id, local_parent, bridge, token, user)
          prod_child_path = "/api/v4/projects/#{CGI.escape(prod_project_id.to_s)}/pipelines/#{prod_child_id}"
          prod_child = ::Gitlab::Json.safe_parse(gitlab_com_get(prod_child_path, token)) || {}

          local_child = ::Ci::Pipeline.new(
            project: local_parent.project,
            ref: prod_child['ref'].presence || local_parent.ref,
            sha: local_parent.sha,
            source: 'parent_pipeline',
            partition_id: local_parent.partition_id,
            user: user
          )
          local_child.status = prod_child['status'].presence || 'failed'
          # Allocate the iid outside the save transaction to avoid a cross-database modification.
          local_child.ensure_project_iid!
          local_child.save!(validate: false)

          ::Ci::Sources::Pipeline.create!(
            project: local_parent.project,
            pipeline: local_child,
            source_project: local_parent.project,
            source_pipeline: local_parent,
            source_job: bridge
          )

          fetch_jobs(prod_project_id, prod_child_id, token).each do |prod_job|
            create_local_build_from_prod(local_child, prod_job, user)
          end

          local_child.reset
        end
        private_class_method :create_local_child_pipeline

        def self.replay_traces(prod_rows, local_project, gitlab_token)
          overrides = []
          prod_rows.each do |row|
            fp_id = row['fp_id']
            next unless eligible_row?(row, fp_id)

            override = replay_one_row(row, fp_id, local_project, gitlab_token)
            overrides << override if override
          end
          overrides
        end
        private_class_method :replay_traces

        def self.replay_one_row(row, fp_id, local_project, gitlab_token)
          source_branch = row['source_branch']
          prod_pipeline_url = row['prod_pipeline_url']

          prod_project_id, prod_pipeline_id = parse_pipeline_url(prod_pipeline_url)
          unless prod_project_id && prod_pipeline_id
            puts "    [#{fp_id}] WARN: cannot parse prod_pipeline_url, skipping"
            return
          end

          local_pipeline = find_local_pipeline(local_project, source_branch)
          unless local_pipeline
            puts "    [#{fp_id}] WARN: no local pipeline on branch #{source_branch}, skipping"
            return
          end

          # A non-branch ref (typically refs/merge-requests/<iid>/head) reaches the flow as
          # `source_branch`, and its `git checkout -B <ref> --track origin/<ref>` cannot resolve it. That
          # failure is silent downstream -- the run reports success having done nothing -- so say it here.
          if local_pipeline.ref != source_branch
            puts "    [#{fp_id}] WARN: pipeline #{local_pipeline.id} is on ref #{local_pipeline.ref}, " \
              "not branch #{source_branch}"
          end

          replayed = replay_pipeline_traces(local_pipeline, prod_project_id, prod_pipeline_id, gitlab_token,
            fp_id: fp_id)
          replayed ||= replay_downstreams(local_pipeline, prod_project_id, prod_pipeline_id, gitlab_token, fp_id)

          local_url = ::Rails.application.routes.url_helpers.project_pipeline_url(local_project, local_pipeline)
          puts "    [#{fp_id}] #{replayed ? 'replayed' : 'override-only (no jobs to replay)'} -> #{local_url}"

          { 'fp_id' => fp_id, 'prod_pipeline_url' => prod_pipeline_url, 'pipeline_url' => local_url }
        end
        private_class_method :replay_one_row

        # Some rows have a trigger-only parent where the real failure lives
        # in a downstream child. File-based export drops cross-pipeline
        # links, so `bridge.downstream_pipeline` is often nil -- we skip
        # those, accepting the fidelity loss vs production.
        def self.replay_downstreams(local_parent, prod_project_id, prod_parent_id, gitlab_token, fp_id)
          replayed = false
          local_parent.bridges.each do |bridge|
            local_child = bridge.downstream_pipeline
            next unless local_child

            prod_child_id = fetch_downstream_pipeline_id(
              prod_project_id, prod_parent_id, bridge.name, gitlab_token
            )
            next unless prod_child_id

            replayed = true if replay_pipeline_traces(
              local_child, prod_project_id, prod_child_id, gitlab_token,
              fp_id: "#{fp_id} (downstream)"
            )
          end
          replayed
        end
        private_class_method :replay_downstreams

        # Returns true iff at least one local job got a trace populated.
        # Replays traces for all job statuses (not just failed) -- some
        # agent diagnoses require inspecting upstream success traces.
        def self.replay_pipeline_traces(local_pipeline, prod_project_id, prod_pipeline_id, token, fp_id:)
          replayed = false
          fetch_jobs(prod_project_id, prod_pipeline_id, token).each do |prod_job|
            local_job = local_pipeline.all_jobs.find_by_name(prod_job['name'])
            if local_job.nil?
              puts "    [#{fp_id}] WARN: no local job named '#{prod_job['name']}'"
              next
            end

            next unless local_job.respond_to?(:trace)

            trace = fetch_job_trace(prod_project_id, prod_job['id'], token)
            next unless trace

            local_job.trace.set(trace)
            replayed = true
          end
          replayed
        end
        private_class_method :replay_pipeline_traces

        # Pick the local pipeline that corresponds to the branch's *current
        # HEAD* commit. The branch can carry several pipelines (a `push`
        # pipeline for an older SHA, a `merge_request_event` pipeline on
        # refs/merge-requests/<iid>/head for the latest SHA, etc.). We want
        # the one whose SHA matches what's checked out today.
        #
        # Among the pipelines at that SHA, prefer a branch pipeline. Production
        # reaches the flow from one, so a branch ref is the faithful fixture; a
        # `merge_request_event` ref is an artifact of mirroring MR pipelines. SHA
        # freshness still wins over ref shape, because a stale pipeline carries the
        # wrong job traces and would mis-describe the failure the catalog expects.
        #
        # The later clauses can therefore still return a non-branch ref, which the
        # flow cannot check out; `replay_one_row` warns when that happens rather
        # than letting the fixture look clean.
        def self.find_local_pipeline(local_project, source_branch)
          head_sha = local_project.commit(source_branch)&.id
          return unless head_sha

          project_pipelines = ::Ci::ProjectPipelines.new(local_project)

          project_pipelines.latest(branch: source_branch, sha: head_sha) ||
            project_pipelines.latest(sha: head_sha) ||
            project_pipelines.latest(ref: source_branch) ||
            local_project.merge_requests.find_by_source_branch(source_branch)
              &.pipelines_for_merge_request
              &.last
        end
        private_class_method :find_local_pipeline

        def self.verify_completeness(prod_rows, local_project)
          missing = []
          prod_rows.each do |row|
            fp_id = row['fp_id']
            next unless eligible_row?(row, fp_id)

            local_pipeline = find_local_pipeline(local_project, row['source_branch'])
            if local_pipeline.nil?
              missing << "[#{fp_id}] no local pipeline on branch '#{row['source_branch']}'"
              next
            end

            missing << "[#{fp_id}] no jobs with replayed traces on pipeline #{local_pipeline.id}" \
              unless pipeline_has_any_trace?(local_pipeline)
          end

          if missing.empty?
            puts '    ok - every row has a local pipeline with at least one replayed trace'
            return true
          end

          puts '    incomplete:'
          missing.each { |m| puts "      - #{m}" }
          false
        end
        private_class_method :verify_completeness

        def self.pipeline_has_any_trace?(local_pipeline)
          return true if jobs_have_any_trace?(local_pipeline.all_jobs)

          # Some parent pipelines are bridge-only; the real failure is downstream.
          local_pipeline.bridges.any? do |bridge|
            child = bridge.downstream_pipeline
            child && jobs_have_any_trace?(child.all_jobs)
          end
        end
        private_class_method :pipeline_has_any_trace?

        def self.jobs_have_any_trace?(jobs)
          # all_jobs includes Ci::Bridge (trigger jobs) which have no .trace.
          jobs.any? do |j|
            next false unless j.respond_to?(:trace) && j.trace.exist?

            begin
              !j.trace.raw.to_s.strip.empty?
            rescue StandardError => e
              puts "    WARN: trace read failed for job #{j.id}: #{e.message}"
              false
            end
          end
        end
        private_class_method :jobs_have_any_trace?

        def self.eligible_row?(row, fp_id)
          if row['authentic'].to_s == 'skipped' || row['source_branch'].blank? || row['prod_pipeline_url'].blank?
            puts "    [#{fp_id}] skipped (incomplete row)"
            return false
          end

          true
        end
        private_class_method :eligible_row?

        def self.find_root_user
          user = User.find_by_username('root')
          abort 'Error: root user not found; please ensure the development environment is set up.' unless user

          user
        end
        private_class_method :find_root_user

        def self.write_url_override_yaml(rows, output_file)
          # Resolve bare filenames against CWD (the GDK Rails root, where the eval consumer reads from).
          path = File.absolute_path?(output_file) ? output_file : File.expand_path(output_file)
          File.write(path, rows.to_yaml)
          path
        end
        private_class_method :write_url_override_yaml

        def self.parse_pipeline_url(url)
          m = url.match(%r{\Ahttps?://[^/]+/(.+?)/-/pipelines/(\d+)})
          m ? [m[1], m[2].to_i] : [nil, nil]
        end
        private_class_method :parse_pipeline_url

        def self.fetch_jobs(project_path_or_id, pipeline_id, token)
          body = gitlab_com_get("/api/v4/projects/#{CGI.escape(project_path_or_id.to_s)}/pipelines/#{pipeline_id}/jobs",
            token)
          ::Gitlab::Json.safe_parse(body) || []
        end
        private_class_method :fetch_jobs

        def self.fetch_job_trace(project_path_or_id, job_id, token)
          gitlab_com_get("/api/v4/projects/#{CGI.escape(project_path_or_id.to_s)}/jobs/#{job_id}/trace",
            token, accept: 'text/plain')
        rescue StandardError => e
          puts "    WARN: trace fetch failed for job #{job_id}: #{e.message}"
          nil
        end
        private_class_method :fetch_job_trace

        def self.fetch_downstream_pipeline_id(prod_project_id, prod_pipeline_id, bridge_name, token)
          return if bridge_name.blank?

          path = "/api/v4/projects/#{CGI.escape(prod_project_id.to_s)}/pipelines/#{prod_pipeline_id}/bridges"
          bridges = ::Gitlab::Json.safe_parse(gitlab_com_get(path, token)) || []
          bridges.find { |b| b['name'] == bridge_name }&.dig('downstream_pipeline', 'id')
        rescue StandardError => e
          puts "    WARN: bridge lookup failed for #{bridge_name}: #{e.message}"
          nil
        end
        private_class_method :fetch_downstream_pipeline_id

        def self.gitlab_com_get(path, token, accept: 'application/json')
          http_get_with_retry(
            "#{SOURCE_GITLAB_URL}#{path}",
            headers: { 'PRIVATE-TOKEN' => token, 'Accept' => accept },
            label: "GET #{path}"
          )
        end
        private_class_method :gitlab_com_get

        def self.fetch_prod_manifest_from_langsmith(api_key)
          endpoint = ENV['LANGCHAIN_ENDPOINT'] || DEFAULT_LANGSMITH_ENDPOINT
          dataset_id = resolve_langsmith_dataset_id(endpoint, SOURCE_LANGSMITH_DATASET, api_key)
          abort "Dataset '#{SOURCE_LANGSMITH_DATASET}' not found at #{endpoint}" unless dataset_id

          body = langsmith_get("#{endpoint}/api/v1/datasets/#{dataset_id}/jsonl", api_key)
          parse_jsonl_rows(body)
        rescue StandardError => e
          abort "Error fetching dataset from LangSmith: #{e.message}"
        end
        private_class_method :fetch_prod_manifest_from_langsmith

        def self.parse_jsonl_rows(body)
          body.each_line.with_object([]) do |line, out|
            parsed = begin
              ::Gitlab::Json.safe_parse(line)
            rescue ::Gitlab::Json.parser_error
              nil
            end
            next unless parsed.is_a?(Hash)

            row = (parsed['inputs'] || {}).merge(parsed['outputs'] || {})
            metadata = parsed['metadata'] || {}
            %w[fp_id authentic].each { |k| row[k] = metadata[k] if row[k].nil? && metadata[k] }
            out << row
          end
        end
        private_class_method :parse_jsonl_rows

        def self.resolve_langsmith_dataset_id(endpoint, name, api_key)
          body = langsmith_get("#{endpoint}/api/v1/datasets?name=#{CGI.escape(name)}&limit=1", api_key)
          parsed = ::Gitlab::Json.safe_parse(body)
          parsed.is_a?(Array) ? parsed.first&.dig('id') : nil
        end
        private_class_method :resolve_langsmith_dataset_id

        def self.langsmith_get(url, api_key)
          http_get_with_retry(
            url,
            headers: { 'X-API-Key' => api_key, 'Content-Type' => 'application/json' },
            label: "GET #{URI(url).path}"
          )
        end
        private_class_method :langsmith_get

        # Wraps Gitlab::HTTP.get with bounded exponential retry on 5xx / connection
        # errors. 4xx is raised immediately. Returns the response body string.
        def self.http_get_with_retry(url, headers:, label:)
          attempt = 0
          loop do
            attempt += 1
            begin
              response = ::Gitlab::HTTP.get(url, headers: headers)
              return response.body.to_s if response.success?

              if HTTP_RETRYABLE_STATUSES.include?(response.code) && attempt < HTTP_RETRY_ATTEMPTS
                wait = HTTP_RETRY_BASE_DELAY_S * (2**(attempt - 1))
                warn "    WARN: #{label} got #{response.code}; retry #{attempt}/#{HTTP_RETRY_ATTEMPTS - 1} in #{wait}s"
                sleep wait
                next
              end

              raise "#{label}: #{response.code} #{response.body.to_s[0..200]}"
            rescue *::Gitlab::HTTP::HTTP_ERRORS => e
              raise if attempt >= HTTP_RETRY_ATTEMPTS

              wait = HTTP_RETRY_BASE_DELAY_S * (2**(attempt - 1))
              warn "    WARN: #{label} #{e.class}: #{e.message}; " \
                "retry #{attempt}/#{HTTP_RETRY_ATTEMPTS - 1} in #{wait}s"
              sleep wait
            end
          end
        end
        private_class_method :http_get_with_retry
      end
    end
  end
end
