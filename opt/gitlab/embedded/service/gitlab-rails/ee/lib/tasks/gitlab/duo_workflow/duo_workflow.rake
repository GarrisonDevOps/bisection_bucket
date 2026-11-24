# frozen_string_literal: true

# Constants for the default values
DEFAULT_TOTAL_COUNT = 50
DEFAULT_PROJECT_PATH = 'gitlab-duo/test'
DEFAULT_CURRENT_USER_COUNT_LIMIT = 24
DEFAULT_ENVIRONMENT_TYPE = 'web'

namespace :gitlab do
  namespace :duo_workflow do
    desc "GitLab | Duo Workflows | Populate fake workflow data"
    # Example usage: bundle exec rake "gitlab:duo_workflow:populate[50,20,1,gitlab-duo/test]"
    # total_count: Total workflows to create (default: 50)
    # current_user_count: Workflows for target user (default: min(total_count, 24))
    # user_id: User ID (default: first available user)
    # project_path: Project path like 'gitlab-org/gitlab' (default: gitlab-duo/test)
    # environment_type: Environment type like 'web' (default: 'web')
    # Note: This task cannot be run in production.
    # Note: this current_user_count cannot be greater than total_count

    # Helper method to create workflow checkpoint data structures

    task :populate, [
      :total_count,
      :current_user_count,
      :user_id,
      :project_path,
      :environment_type
    ] => :environment do |_t, args|
      raise 'This task cannot be run in production' if Rails.env.production?

      # rubocop:disable Rake/TopLevelMethodDefinition -- Instance methods within task scope do not leak
      def create_checkpoint_data(workflow_goal, workflow_status, step = 0, parent_ts = nil)
        # rubocop:enable Rake/TopLevelMethodDefinition
        timestamp = Time.current.iso8601(6)

        # Create checkpoint JSONB data
        checkpoint_data = {
          "v" => 1,
          "id" => Gitlab::Utils.uuid_v7,
          "ts" => timestamp,
          "pending_sends" => [],
          "versions_seen" => {
            "__input__" => {},
            "__start__" => { "__start__" => 1 }
          },
          "channel_values" => {
            "plan" => { "steps" => [] },
            "status" => workflow_status,
            "handover" => [],
            "ui_chat_log" => [
              {
                "status" => "success",
                "timestamp" => timestamp,
                "tool_info" => nil,
                "message_type" => "tool",
                "correlation_id" => nil,
                "content" => <<~MARKDOWN
                Starting workflow with goal: #{workflow_goal}. This should always be escaped because goals can come from users!
                 Test user content that should be escaped
                 <img src="https://en.wikipedia.org/wiki/Wikipedia#/media/File:Wikipedia-logo-v2.svg">
                 <h1>My own markdown!!!!</h1>
                 <pre>Tons of stuff</pre>
                 for file file_path_that_is_super_long/another_directoryandasinglewordthatsjustsolongitshouldwrap
                MARKDOWN
              },
              {
                "status" => "success",
                "content" => "Read file",
                "timestamp" => timestamp,
                "tool_info" => { name: 'read_file',
                                 args: {
                                   file_path:
                                   'app/assets/very-long-path/that-wont-end/ohnopleasehelpmeIamgoingoffscreenaaaaaaaaaa'
                                 } },
                "message_type" => "tool",
                "correlation_id" => nil
              },
              {
                "status" => "success",
                "content" => "Read issue http://gdk.test:3000/gitlab-duo/test/-/issues/1",
                "timestamp" => timestamp,
                "tool_info" => { name: 'get_issue' },
                "message_type" => "tool",
                "correlation_id" => nil
              },
              {
                "status" => "success",
                "content" => "Can you tell me more about your project?",
                "timestamp" => timestamp,
                "tool_info" => nil,
                "message_type" => "request",
                "correlation_id" => nil
              },
              {
                "status" => "success",
                "content" => "Yes, please add test coverage please.",
                "timestamp" => timestamp,
                "tool_info" => nil,
                "message_type" => "user",
                "correlation_id" => nil
              },
              {
                "status" => "success",
                "timestamp" => timestamp,
                "tool_info" => nil,
                "message_type" => "agent",
                "correlation_id" => nil,
                "content" => <<~MARKDOWN
                  I have successfully built comprehensive context around GitLab issue #569671 and identified the specific development tasks required.
                  Here's the complete analysis:

                  ## Issue Context

                  **Title:** "Removed locked discussion banner on wikis in archived groups/projects"

                  **Issue ID:** #569671

                  **Epic:** Part of epic #18912 "Prevent write permissions when the group is archived"
                MARKDOWN
              },
              {
                "status" => "success",
                "message_type" => "user",
                "content" => <<~MARKDOWN
                 Test user content that should be escaped
                 <img src="https://en.wikipedia.org/wiki/Wikipedia#/media/File:Wikipedia-logo-v2.svg">
                 <h1>My own markdown!!!!</h1>
                 <pre>Tons of stuff</pre>
                MARKDOWN
              },
              {
                "status" => "success",
                "message_type" => "workflow_end",
                "content" => <<~MARKDOWN
                  Summary of my task and other really cool insights.
                  # H1 title

                  ## H2 title

                  ## H3 Title

                  This is some content.

                  <pre>
                    <failure_2>
                      <test_name>TestAgent.test_run_with_empty_conversation</test_name>
                      <location>tests/duo_workflow_service/agents/test_agent.py</location>
                      <error_type>AssertionError</error_type>
                      <description>AIMessage object comparison failed due to additional fields in actual result</description>
                      <expected>AIMessage(content='Hello there!', additional_kwargs={}, response_metadata={})</expected>
                      <actual>AIMessage(content='Hello there!', additional_kwargs={}, response_metadata={}, id='run--467148e1-9150-4c46-8711-8322b66957d3-0', usage_metadata={'total_cost': 0})</actual>
                      <root_cause>The actual AIMessage contains additional fields (id and usage_metadata) that are not expected in the test assertion</root_cause>
                    </failure_2>
                </test_failures>

                <test_summary>
                  <total_tests>4549</total_tests>
                  <passed>4544</passed>
                  <failed>2</failed>
                  <skipped>3</skipped>
                  <warnings>227</warnings>
                  <coverage>93%</coverage>
                </test_summary></pre>

                  Also don't forget to check out the **bold** words. You can also use _italics_.
                MARKDOWN
              }
            ],
            "last_human_input" => nil,
            "start:build_context" => "__start__",
            "conversation_history" => {}
          },
          "channel_versions" => {
            "plan" => 2,
            "status" => 2,
            "handover" => 2,
            "__start__" => 2,
            "ui_chat_log" => 2,
            "last_human_input" => 2,
            "start:build_context" => 2,
            "conversation_history" => 2
          }
        }

        # Create metadata JSONB data
        metadata = {
          "step" => step,
          "source" => "loop",
          "writes" => nil,
          "parents" => {},
          "thread_id" => SecureRandom.random_number(1000000).to_s
        }

        {
          parent_ts: parent_ts,
          thread_ts: Gitlab::Utils.uuid_v7,
          checkpoint: checkpoint_data,
          metadata: metadata
        }
      end

      # Incremental checkpoint blobs for one checkpoint, in the shape the gateway
      # posts them: zlib-compressed JSON, base64 encoded. A seeded checkpoint holds a
      # full snapshot of every channel, so step_action replaces instead of appends.
      # rubocop:disable Rake/TopLevelMethodDefinition -- Instance methods within task scope do not leak
      def build_channel_blobs(checkpoint)
        # rubocop:enable Rake/TopLevelMethodDefinition
        checkpoint.fetch("channel_values", {}).map do |channel, value|
          {
            channel: channel,
            version: (checkpoint.dig("channel_versions", channel) || 1).to_s,
            write_type: "json",
            step_action: "compaction",
            data: Base64.strict_encode64(Zlib::Deflate.deflate(Gitlab::Json.dump(value)))
          }
        end
      end

      # Parse and validate total_count argument
      if args.total_count.blank?
        total_count = DEFAULT_TOTAL_COUNT
      else
        total_count = args.total_count.to_i
        if total_count <= 0
          puts Rainbow("Error: total_count must be a positive integer, got: #{args.total_count}").red
          exit 1
        end
      end

      # Default current_user_count to min(total_count, DEFAULT_CURRENT_USER_COUNT_LIMIT) but at least 1
      default_current_user_count = [[total_count, DEFAULT_CURRENT_USER_COUNT_LIMIT].min, 1].max

      # Parse and validate current_user_count argument
      if args.current_user_count.blank?
        current_user_count = default_current_user_count
      else
        current_user_count = args.current_user_count.to_i
        if current_user_count <= 0
          puts Rainbow("Error: current_user_count must be a positive integer, got: #{args.current_user_count}").red
          exit 1
        end
      end

      # Resolve target user
      if args.user_id.present?
        # Try to find by ID first, then by email, then by username
        target_user = if args.user_id.to_s.match?(/\A\d+\z/)
                        User.find_by(id: args.user_id.to_i)
                      else
                        User.find_by(email: args.user_id) || User.find_by(username: args.user_id)
                      end

        if target_user.nil?
          puts Rainbow("Error: User not found with identifier: #{args.user_id}").red
          puts "Try using a valid user ID, email, or username."
          exit 1
        end
      else
        # Use first available user as fallback
        target_user = User.first
        if target_user.nil?
          puts Rainbow("Error: No users found in database. Please create a user first.").red
          exit 1
        end

        puts Rainbow("No user specified, using first available user:
          #{target_user.username} (#{target_user.email})").yellow
      end

      # Resolve target project
      if args.project_path.present?
        target_project = Project.find_by_full_path(args.project_path)

        if target_project.nil?
          puts Rainbow("Error: Project not found with path: #{args.project_path}").red
          puts "Try using a valid project path like 'gitlab-org/gitlab'."
          exit 1
        end
      else
        # Default to gitlab-duo/test
        default_path = DEFAULT_PROJECT_PATH
        target_project = Project.find_by_full_path(default_path)

        if target_project
          puts Rainbow("No project specified, using default project: #{default_path}").yellow
        else
          # Fall back to first available project if default doesn't exist
          target_project = Project.first
          if target_project.nil?
            puts Rainbow("Error: No projects found in database. Please create a project first.").red
            exit 1
          end

          puts Rainbow("Default project '#{default_path}' not found,
            using first available project: #{target_project.full_path}").yellow
        end
      end

      # Set environment type
      environment_type = args.environment_type.presence || DEFAULT_ENVIRONMENT_TYPE

      # Validate arguments
      if current_user_count > total_count
        puts Rainbow("Error: current_user_count (#{current_user_count})
        cannot be greater than total_count (#{total_count})").red
        puts "Usage: rake gitlab:duo_workflows:populate[total_count,current_user_count,user_id,project_path]"
        puts "  total_count: Total workflows to create (default: #{DEFAULT_TOTAL_COUNT})"
        puts "  current_user_count: Workflows for target user (default: min(total_count,
          #{DEFAULT_CURRENT_USER_COUNT_LIMIT}))"
        puts "  user_id: User ID or email (default: first available user)"
        puts "  project_path: Project path like 'gitlab-org/gitlab' (default: #{DEFAULT_PROJECT_PATH})"
        exit 1
      end

      puts "Creating #{total_count} fake Ai::DuoWorkflows::Workflow entities..."
      puts "#{current_user_count} will be assigned to user: #{target_user.username} (#{target_user.email})"
      puts "All workflows will be assigned to project: #{target_project.full_path}"
      puts "All workflows will use environment type: #{environment_type}"

      # Sample goals for workflows
      sample_goals = [
        "Create a new user authentication system",
        "Implement API rate limiting",
        "Add database migration for user preferences",
        "Fix memory leak in background jobs",
        "Optimize database queries for dashboard",
        "Add unit tests for payment processing",
        "Implement OAuth2 integration",
        "Create automated deployment pipeline",
        "Add logging and monitoring",
        "Refactor legacy code modules",
        "Implement caching layer",
        "Add email notification system",
        "Create admin dashboard",
        "Fix security vulnerabilities",
        "Add mobile API endpoints",
        "Implement search functionality",
        "Add data export feature",
        "Create backup and restore system",
        "Implement real-time notifications",
        "Add multi-language support",
        "Optimize frontend performance",
        "Add GraphQL API endpoints",
        "Implement file upload system",
        "Create user onboarding flow",
        "Add two-factor authentication",
        "Implement role-based permissions",
        "Create reporting dashboard",
        "Add webhook integration",
        "Implement data validation",
        "Create API documentation"
      ]

      # Sample workflow definitions
      workflow_definitions = %w[software_development chat convert_to_gitlab_ci]

      # Sample statuses (using the state machine values)
      statuses = [0, 1, 2, 3, 4, 5, 6, 7, 8]

      # Get some existing users for associations, excluding the target user
      users = User.where.not(id: target_user.id).limit(10).pluck(:id)

      if users.empty?
        puts Rainbow("Warning: No other users found besides target user. Creating a test user...").yellow
        user = User.create!(
          email: "test-workflow-user@example.com",
          username: "workflow-test-user",
          name: "Workflow Test User",
          password: "password123",
          password_confirmation: "password123"
        )
        users = [user.id]

      end

      workflows_created = 0
      checkpoints_created = 0
      pipelines_created = 0
      workloads_created = 0
      errors = []

      total_count.times do |i|
        # Random agent privileges (using the constants from the model)
        available_privileges = [
          Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_FILES,
          Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB,
          Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_GITLAB,
          Ai::DuoWorkflows::Workflow::AgentPrivileges::RUN_COMMANDS,
          Ai::DuoWorkflows::Workflow::AgentPrivileges::USE_GIT
        ]

        # Select 2-4 random privileges
        agent_privileges = available_privileges.sample(rand(2..4))

        # Pre-approved privileges should be a subset of agent privileges
        pre_approved_privileges = agent_privileges.sample(rand(1..agent_privileges.length))

        # Determine user_id: use target user for first current_user_count workflows
        user_id = if i < current_user_count
                    target_user.id
                  else
                    users.sample
                  end

        goal = "#{sample_goals.sample} (Workflow ##{i + 1})"
        workflow_status = statuses.sample

        workflow = Gitlab::Database::QueryAnalyzers::PreventCrossDatabaseModification
          .allow_cross_database_modification_within_transaction(
            url: 'gitlab-issue'
          ) do
            workflow = Ai::DuoWorkflows::Workflow.create!(
              user_id: user_id,
              project_id: target_project.id,
              goal: goal,
              status: workflow_status,
              workflow_definition: workflow_definitions.sample,
              agent_privileges: agent_privileges,
              pre_approved_agent_privileges: pre_approved_privileges,
              allow_agent_to_request_user: [true, false].sample,
              environment: environment_type,
              incremental_checkpoints_enabled: true
            )

            # Create a fake pipeline and workload for the workflow to provide lastExecutorLogsUrl
            pipeline = Ci::Pipeline.create!(
              project: target_project,
              user: User.find(user_id),
              ref: target_project.default_branch || 'main',
              sha: target_project.repository.commit&.sha || 'fake_sha',
              status: 'success',
              source: 'web'
            )

            workload = Ci::Workloads::Workload.create!(
              project: target_project,
              pipeline: pipeline
            )

            ci_stage = pipeline.stages.create!(
              project: target_project,
              name: 'test',
              position: 0,
              status: 'success',
              partition_id: pipeline.partition_id
            )

            Ci::Build.create!(
              pipeline: pipeline,
              project: target_project,
              user: User.find(user_id),
              ref: pipeline.ref,
              name: 'duo-workflow-executor',
              ci_stage: ci_stage,
              status: 'success',
              scheduling_type: 'stage',
              partition_id: pipeline.partition_id
            )

            Ai::DuoWorkflows::WorkflowsWorkload.create!(
              workflow: workflow,
              workload: workload,
              project: target_project
            )

            workflow
          end

        workflows_created += 1
        pipelines_created += 1
        workloads_created += 1

        # Create workflow checkpoints based on workflow status
        # Map workflow status to checkpoint configurations
        checkpoint_configs = case workflow_status
                             # created, running
                             when 0, 1
                               [
                                 { workflow_status: 'STARTED' }
                               ]
                             # paused, finished, failed
                             when 2, 3, 4
                               [
                                 { workflow_status: 'STARTED' },
                                 { workflow_status: 'IN_PROGRESS' }
                               ]
                             # stopped, input_required, plan_approval_required, tool_call_approval_required
                             when 5, 6, 7, 8
                               [
                                 { workflow_status: 'STARTED' },
                                 { workflow_status: 'IN_PROGRESS' },
                                 { workflow_status: 'FINISHED' }
                               ]
                             else
                               # Default case for any unexpected status values
                               [
                                 { workflow_status: 'IN_PROGRESS' }
                               ]
                             end

        # Create workflow checkpoints. Each one parents the next, so the seeded
        # thread_ts chain walks like a real session (see Workflow#ancestor_thread_ts).
        parent_ts = nil

        checkpoint_configs.each_with_index do |config, checkpoint_index|
          checkpoint_data = create_checkpoint_data(goal, config[:workflow_status], checkpoint_index, parent_ts)

          # The production write path, so seeded sessions get checkpoint headers and
          # blobs instead of the legacy full row alone.
          result = Ai::DuoWorkflows::CreateCheckpointService.new(
            workflow: workflow,
            params: {
              thread_ts: checkpoint_data[:thread_ts],
              parent_ts: checkpoint_data[:parent_ts],
              checkpoint: checkpoint_data[:checkpoint],
              metadata: checkpoint_data[:metadata],
              current_thread: 0,
              channel_blobs: build_channel_blobs(checkpoint_data[:checkpoint])
            }
          ).execute

          if result[:status] == :error
            reason = Array.wrap(result[:message]).join(", ").presence || "unknown error"
            raise "checkpoint #{checkpoint_data[:thread_ts]} on workflow #{workflow.id} failed: #{reason}"
          end

          parent_ts = checkpoint_data[:thread_ts]
          checkpoints_created += 1
        end

        print "." if (i + 1) % 10 == 0

      rescue StandardError => e
        errors << "Error creating workflow #{i + 1}: #{e.message}"
      end

      puts "\n\nSuccessfully created #{workflows_created} Ai::DuoWorkflows::Workflow entities!"
      puts "Successfully created #{checkpoints_created} workflow checkpoints!"
      puts "Successfully created #{pipelines_created} Ci::Pipeline entities!"
      puts "Successfully created #{workloads_created} Ci::Workloads::Workload entities!"
      puts "#{current_user_count} workflows assigned to target user (#{target_user.username})"
      puts "#{workflows_created - current_user_count} workflows assigned to other users"
      puts "Total workflows in database: #{Ai::DuoWorkflows::Workflow.count}"
      puts "Total workflow checkpoints in database: #{Ai::DuoWorkflows::Checkpoint.count}"
      puts "Total checkpoint headers in database: #{Ai::DuoWorkflows::CheckpointHeader.count}"
      puts "Total checkpoint blobs in database: #{Ai::DuoWorkflows::CheckpointBlob.count}"

      if errors.any?
        puts "\nErrors encountered:"
        errors.each { |error| puts Rainbow("  - #{error}").red }
      end
    end
  end
end
