# frozen_string_literal: true

module Gitlab
  module Duo
    module Developments
      class SweBenchSeeder
        require_relative 'swe_bench_seeder/config'
        require_relative 'swe_bench_seeder/group_manager'
        require_relative 'swe_bench_seeder/repository_manager'
        require_relative 'swe_bench_seeder/issue_manager'
        require_relative 'swe_bench_seeder/dataset_processor'
        require_relative 'swe_bench_seeder/langsmith_client'
        require_relative 'swe_bench_seeder/agent_config_manager'

        DEVELOPER_FLOW_REFERENCE = 'developer/v1'
        private_constant :DEVELOPER_FLOW_REFERENCE

        # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity -- Main orchestration method
        def self.seed(project_filter: nil)
          puts "Seeding SWE Bench data structure..."
          puts "Filtering to projects: #{project_filter.join(', ')}" if project_filter

          ensure_local_url_allowed

          user = User.find_by_username('root')
          parent_group = GroupManager.find_or_create_parent_group(user)
          subgroup = GroupManager.find_or_create_subgroup(parent_group, user)

          puts "Subgroup URL: #{Config.seed_base_url}/#{subgroup.full_path}"

          # Fetch dataset first -- needed for both cleanup scoping and seeding.
          dataset, _dataset_name, _split_name = DatasetProcessor.fetch_dataset_from_langsmith
          return if dataset.empty?

          examples = DatasetProcessor.filter_by_project(dataset, project_filter).select do |e|
            e['inputs']['instance_id'] && e['inputs']['repo'] &&
              e['inputs']['base_commit'] && e['inputs']['problem_statement']
          end

          # When no filter is active, wipe the whole subgroup for a clean slate.
          # When a filter is active, only destroy the specific instance projects being
          # re-seeded -- leave all other already-seeded projects untouched.
          if project_filter&.any?
            examples.each do |e|
              instance_id = e['inputs']['instance_id']
              project_name = RepositoryManager.instance_id_to_project_name(instance_id)
              project = Project.find_by_full_path("#{subgroup.full_path}/#{project_name}")
              next unless project

              puts "Destroying existing project for re-seed: #{project.full_path}"
              ::Projects::DestroyService.new(project, user, {}).execute # rubocop:disable Gitlab/HardDeleteCalls -- Dev-only seeder, not production data
            end
          else
            IssueManager.destroy_instance_projects(subgroup, user)
          end

          puts "\n=== Processing examples from SWE Bench Dataset ==="
          puts "==========================================\n"

          issue_data = []

          puts "Found #{examples.size} example(s) to seed\n"

          # Fire all mirrors + forks in parallel, wait with a single polling loop
          projects_by_instance = RepositoryManager.setup_instance_projects(examples, subgroup, user)

          # Commit agent config and create issue for each successfully seeded project
          projects_by_instance.each do |instance_id, project|
            example = examples.find { |e| e['inputs']['instance_id'] == instance_id }
            next unless example

            inputs = example['inputs']

            AgentConfigManager.commit_agent_config(project, user, instance_id: instance_id)

            issue = IssueManager.create_issue_from_problem_statement(project, user, inputs['problem_statement'])
            next unless issue

            issue_url = Rails.application.routes.url_helpers.project_issue_url(project, issue)

            issue_data << {
              inputs: { issue_url: issue_url, **inputs },
              outputs: example['outputs']
            }
          end

          puts "\n#{'=' * 60}"
          puts "SEEDING COMPLETE: #{projects_by_instance.size}/#{examples.size} project(s) seeded"
          puts "=" * 60

          if projects_by_instance.size < examples.size
            raise "Seeding incomplete: only #{projects_by_instance.size}/#{examples.size} projects seeded successfully."
          end

          save_to_langsmith = ENV['SAVE_TO_LANGSMITH'].presence
          if save_to_langsmith.present? && issue_data.any?
            LangsmithClient.save_issue_urls_to_langsmith(issue_data, save_to_langsmith)
          end

          # Wire up the developer/v1 foundational flow so the eval harness can
          # trigger Duo Developer via Ai::Catalog::Flows::ExecuteService -- the
          # same code path used in production when a user assigns the
          # `duo-developer` service account to an issue.
          ensure_developer_foundational_flow!(parent_group, user)
        rescue StandardError => e
          puts "Error seeding SWE Bench structure: #{e.message}"
          puts e.backtrace.first(5).join("\n")
          raise
        end

        # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

        # Provisions per-project `Ai::Catalog::ItemConsumer` rows + `:assign`
        # / `:mention` flow triggers for the developer/v1 foundational flow
        # under the `gitlab-duo` namespace. This is what allows the CEF eval
        # harness to trigger Duo Developer by assigning the per-namespace
        # `duo-developer-<root-namespace-path>` service account to the seeded
        # issue: GitLab's `:assign` FlowTrigger fires the production code
        # path that renders the goal template server-side and starts the
        # workflow via `Ai::Catalog::Flows::ExecuteService`.
        #
        # Idempotent: re-running the seeder after consumers exist is a no-op
        # (relies on `find_or_create` inside SyncFoundationalFlowsService and
        # the `idempotent!` declaration on the cascade worker).
        #
        # Requires `gitlab:duo:onboard_dap` to have run first (creates the
        # instance-wide `duo-developer` service account that the cascade
        # worker uses as a template to clone the per-namespace shadow service
        # account). If it hasn't, the worker still runs but the resulting
        # consumers won't have a service account and the :assign trigger
        # filter (`by_service_accounts(...)`) will silently skip them.
        def self.ensure_developer_foundational_flow!(parent_group, admin_user)
          unless catalog_support_available?
            puts "Skipping foundational-flow setup: Ai::Catalog classes not defined on this GitLab checkout."
            return
          end

          unless admin_user&.can_admin_all_resources?
            puts "Skipping foundational-flow setup: no admin user (need :provision_ai_catalog)."
            return
          end

          unless parent_group
            puts "Skipping foundational-flow setup: parent group not provided."
            return
          end

          enable_foundational_flow_cascade_flags!(parent_group)

          puts "Seeding Ai::Catalog::Item rows for foundational flows..."
          ::Ai::Catalog::Flows::SeedFoundationalFlowsService.new.execute

          dev_item = ::Ai::Catalog::FoundationalFlow
            .find_by(foundational_flow_reference: DEVELOPER_FLOW_REFERENCE) # rubocop:disable CodeReuse/ActiveRecord -- Dev-only seeder
            &.catalog_item

          unless dev_item
            puts "Skipping foundational-flow setup: developer/v1 catalog item not seeded."
            return
          end

          puts "Enabling #{DEVELOPER_FLOW_REFERENCE} (catalog_item_id=#{dev_item.id}) on " \
            "#{parent_group.full_path}..."
          parent_group.sync_enabled_foundational_flows!([dev_item.id])

          puts "Running CascadeSyncFoundationalFlowsWorker inline for " \
            "#{parent_group.full_path} (admin=#{admin_user.username})..."
          ::Ai::Catalog::Flows::CascadeSyncFoundationalFlowsWorker
            .new
            .perform(parent_group.id, admin_user.id)

          log_post_sync_summary(parent_group, dev_item)
        end

        def self.catalog_support_available?
          defined?(::Ai::Catalog::Flows::SeedFoundationalFlowsService) &&
            defined?(::Ai::Catalog::Flows::CascadeSyncFoundationalFlowsWorker) &&
            defined?(::Ai::Catalog::FoundationalFlow)
        end
        private_class_method :catalog_support_available?

        def self.enable_foundational_flow_cascade_flags!(group)
          settings = group.namespace_settings || group.build_namespace_settings
          changed = false
          if settings.respond_to?(:duo_features_enabled) && !settings.duo_features_enabled
            settings.duo_features_enabled = true
            changed = true
          end

          if settings.respond_to?(:duo_foundational_flows_enabled) &&
              !settings.duo_foundational_flows_enabled
            settings.duo_foundational_flows_enabled = true
            changed = true
          end

          settings.save! if changed

          puts "Namespace #{group.full_path}: duo settings " \
            "#{changed ? 'updated' : 'already enabled'}"
        end
        private_class_method :enable_foundational_flow_cascade_flags!

        # rubocop:disable CodeReuse/ActiveRecord -- Dev-only seeder
        def self.log_post_sync_summary(parent_group, dev_item)
          descendant_namespace_ids = parent_group.self_and_descendants.select(:id)
          project_count = Project.in_namespace(descendant_namespace_ids).count
          consumer_count = dev_item.consumers
            .where(project_id: Project.in_namespace(descendant_namespace_ids).select(:id))
            .count

          puts "Foundational-flow sync done: #{consumer_count}/#{project_count} " \
            "project(s) under #{parent_group.full_path} have a " \
            "#{DEVELOPER_FLOW_REFERENCE} consumer."
        end
        # rubocop:enable CodeReuse/ActiveRecord
        private_class_method :log_post_sync_summary

        # Ensure the seed_base_url hostname is in the outbound local requests
        # allowlist so that Sidekiq import workers can clone from local mirrors
        # without being blocked by DNS rebinding protection.
        def self.ensure_local_url_allowed
          seed_host = URI.parse(Config.seed_base_url).host
          return unless seed_host

          settings = ApplicationSetting.current_without_cache
          allowlist = settings.outbound_local_requests_whitelist || [] # rubocop:disable Naming/InclusiveLanguage -- existing setting
          return if allowlist.include?(seed_host)

          settings.update!(outbound_local_requests_whitelist: allowlist + [seed_host])
          puts "Added '#{seed_host}' to outbound local requests allowlist"
        end
      end
    end
  end
end
