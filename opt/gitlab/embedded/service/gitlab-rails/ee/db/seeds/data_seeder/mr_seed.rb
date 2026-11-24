# frozen_string_literal: true

class DataSeeder
  NUM_MERGE_REQUESTS = ENV['NUM_MERGE_REQUESTS_TO_SEED'].to_i
  NUM_COMMITS_PER_MR = ENV['NUM_COMMITS_PER_MR_TO_SEED'].to_i

  # Larger payload than create_multiple_merge_requests_with_factory, for /commits, /diffs, /discussions.
  # LARGE_MR_COMMITS exceeds NUM_COMMITS_PER_MR (default 20) so the large MR has a bigger payload.
  LARGE_MR_BRANCH = 'feature/test-seed-large-mr'
  LARGE_MR_COMMITS = 25
  LARGE_MR_FILE = 'lib/test_seed_large_feature.rb'

  # Default (300/min) is too low for sustained k6 load; raised well above CPT's test traffic.
  SEARCH_RATE_LIMIT = 100_000

  def seed
    puts "################### RAISING SEARCH RATE LIMITS FOR LOAD TESTING ###################"
    raise_search_rate_limits

    puts "################### CREATING USER WITH FACTORY ###################"
    @user = create_user_with_factory

    puts "################### CREATING THE GROUP WITH FACTORY ###################"
    @group = create_group_with_factory

    puts "################### CREATING THE PROJECT WITH FACTORY ###################"
    @project = create_project_with_factory

    puts "################### CREATING THE REPOSITORY WITH FACTORY ###################"
    create_repository_for_project

    puts "################### CREATING THE GROUP LABELS WITH FACTORY ###################"
    create_group_labels_with_factories

    puts "########### CREATING #{NUM_MERGE_REQUESTS} MERGE REQUESTS WITH #{NUM_COMMITS_PER_MR} COMMITS EACH ###########"
    create_multiple_merge_requests_with_factory

    puts "################### CREATING LARGE MERGE REQUEST WITH DISCUSSIONS ###################"
    create_large_merge_request_with_discussions
  end

  private

  # Not restored: CPT's CNG deployment is single-use and torn down after the pipeline job.
  # Uses current_without_cache (like db/fixtures/development/28_integrations.rb) to always get
  # an ActiveRecord object; Gitlab::CurrentSettings can return FakeApplicationSettings during
  # rake tasks when migrations are pending, which has no update! and raises NoMethodError.
  def raise_search_rate_limits
    ApplicationSetting.current_without_cache.update!(
      search_rate_limit: SEARCH_RATE_LIMIT,
      search_rate_limit_unauthenticated: SEARCH_RATE_LIMIT
    )
  rescue StandardError => e
    puts "Failed to raise search rate limits, error: #{e.message}"
    exit(1)
  end

  # The instance's Default organization (see gitlab!238769).
  def default_organization
    @default_organization ||= Organizations::Organization.find_by(path: 'default') || # rubocop:disable CodeReuse/ActiveRecord -- allowed in data seeder scripts
      raise('Default organization not found. Cannot seed data without an existing organization.')
  end

  def create_user_with_factory
    existing_user = User.find_by(username: 'test_seed_dev') # rubocop:disable CodeReuse/ActiveRecord -- allowed in data seeder scripts:warn
    if existing_user
      puts 'Using existing test seed user'
      return existing_user
    end

    user = create(:user,
      name: 'Test Seed Developer',
      username: 'test_seed_dev',
      email: "test_seed_dev_#{SecureRandom.hex(8)}@example.com",
      organization: default_organization
    )
    puts 'Created test seed user'
    user
  end

  def create_group_with_factory
    # Use fixed path for idempotency - allows re-running the seed
    group_path = 'test-seed-group'

    existing_group = Group.find_by(path: group_path) # rubocop:disable CodeReuse/ActiveRecord -- allowed in data seeder scripts:warn
    if existing_group
      puts 'Using existing test seed group'
      return existing_group
    end

    group = create(:group,
      name: 'Test Seed Group',
      path: group_path,
      description: 'A group for Test Seed testing',
      visibility_level: Gitlab::VisibilityLevel::PRIVATE,
      organization: default_organization
    )

    group.add_owner(@user)
    puts 'Created test seed group'
    group
  end

  def create_project_with_factory
    # Use fixed path for idempotency - allows re-running the seed
    project_path = 'test-seed-project'

    existing_project = @group.projects.find_by(path: project_path) # rubocop:disable CodeReuse/ActiveRecord -- allowed in data seeder scripts:warn
    if existing_project
      puts 'Using existing test seed project'
      return existing_project
    end

    project = create(:project,
      name: 'Test Seed Project',
      path: project_path,
      namespace: @group,
      description: 'A test project for Test Seed with dummy repository',
      visibility_level: Gitlab::VisibilityLevel::PRIVATE,
      creator: @user,
      organization: default_organization
    )
    puts 'Created test seed project'
    project
  end

  def create_repository_for_project
    if @project.repository_exists?
      puts 'Repository already exists'
      return
    end

    @project.create_repository
    puts 'Created repository'

    # Add user to project with developer access before creating files
    @project.add_developer(@user) unless @project.member?(@user)

    # Verify the user's email so commits pass the commit_committer_check push rule
    @user.emails.update_all(confirmed_at: Time.current)
    # Create initial commit using skip_ci flag to bypass pre-receive hooks
    create_initial_commit_with_skip_ci
  end

  def create_initial_commit_with_skip_ci
    # Use system/admin user to bypass SSH key requirement
    @project.repository.raw_repository.commit_files(
      system_user,
      branch_name: default_branch,
      message: 'Initial commit',
      actions: [
        {
          action: :create,
          file_path: 'README.md',
          content: "# #{@project.name}\n\nWelcome to test seed Project!"
        }
      ],
      force: true
    )
    puts 'Created initial commit'
  rescue Gitlab::Git::CommandError => e
    puts "Failed to create initial commit, error: #{e.message}"
    exit(1)
  end

  def default_branch
    @default_branch ||= @project.default_branch || 'main'
  end

  def system_user
    @system_user ||= User.find_by(username: 'root') || User.admins.first # rubocop:disable CodeReuse/ActiveRecord,Style/InlineDisableAnnotation
  end

  def create_group_labels_with_factories
    labels_data = [
      { title: 'priority::1', color: '#FF0000' },
      { title: 'priority::2', color: '#DD0000' },
      { title: 'priority::3', color: '#CC0000' },
      { title: 'priority::4', color: '#CC1111' }
    ]

    labels_data.each do |label_data|
      create_group_label_with_factory(label_data[:title], label_data[:color])
    end
  end

  def create_group_label_with_factory(title, color)
    return if @group.labels.exists?(title: title) # rubocop:disable CodeReuse/ActiveRecord -- allowed in data seeder scripts:warn

    create(:group_label,
      group: @group,
      title: title,
      color: color
    )
  end

  def create_multiple_merge_requests_with_factory
    NUM_MERGE_REQUESTS.times do |mr_index|
      mr_number = mr_index + 1
      branch_name = "feature/test-seed-feature-#{mr_number}"

      # Check if MR already exists
      existing_mr = @project.merge_requests.find_by(source_branch: branch_name) # rubocop:disable CodeReuse/ActiveRecord -- allowed in data seeder scripts:warn
      if existing_mr
        puts "Merge request #{mr_number} already exists"
        next
      end

      puts "Creating merge request #{mr_number}/#{NUM_MERGE_REQUESTS}..."

      # Create feature branch with multiple commits
      create_feature_branch_with_multiple_commits(branch_name, mr_number)

      # Create merge request
      create(:merge_request,
        title: "Add test seed feature #{mr_number} implementation",
        description: "This MR adds feature #{mr_number} for test seed with documentation and tests",
        source_project: @project,
        target_project: @project,
        source_branch: branch_name,
        target_branch: @project.default_branch || 'main',
        author: @user
      )
      puts "Created merge request #{mr_number}"
    end
  end

  def create_feature_branch_with_multiple_commits(branch_name, mr_number)
    if @project.repository.branch_exists?(branch_name)
      puts "Feature branch #{branch_name} already exists"
      return
    end

    # Create initial commit with feature class
    @project.repository.raw_repository.commit_files(
      system_user,
      branch_name: branch_name,
      start_branch_name: default_branch,
      message: "Add TestSeedFeature#{mr_number} class",
      actions: [
        {
          action: :create,
          file_path: "lib/test_seed_feature_#{mr_number}.rb",
          content: <<~RUBY
            # frozen_string_literal: true

            class TestSeedFeature#{mr_number}
              def initialize(name)
                @name = name
              end

              def greet
                "Hello, \#{@name}! This is test seed feature #{mr_number}."
              end
            end
          RUBY
        }
      ],
      force: true
    )

    # Create additional commits (NUM_COMMITS_PER_MR - 1 more commits)
    (NUM_COMMITS_PER_MR - 1).times do |commit_index|
      commit_number = commit_index + 2
      @project.repository.raw_repository.commit_files(
        system_user,
        branch_name: branch_name,
        message: "Add commit #{commit_number} for feature #{mr_number}",
        actions: [
          {
            action: :create,
            file_path: "lib/test_seed_feature_#{mr_number}_commit_#{commit_number}.rb",
            content: <<~RUBY
              # frozen_string_literal: true

              class TestSeedFeature#{mr_number}Commit#{commit_number}
                def self.description
                  "This is commit #{commit_number} for feature #{mr_number}"
                end
              end
            RUBY
          }
        ],
        force: true
      )
    end

    # Add test file as final commit
    @project.repository.raw_repository.commit_files(
      system_user,
      branch_name: branch_name,
      message: "Add tests for TestSeedFeature#{mr_number}",
      actions: [
        {
          action: :create,
          file_path: "spec/test_seed_feature_#{mr_number}_spec.rb",
          content: <<~RUBY
            # frozen_string_literal: true

            require 'spec_helper'

            RSpec.describe TestSeedFeature#{mr_number} do
              describe '#greet' do
                it 'returns a greeting from Test Seed' do
                  feature = TestSeedFeature#{mr_number}.new('World')
                  expect(feature.greet).to eq('Hello, World! This is test seed feature #{mr_number}.')
                end
              end
            end
          RUBY
        }
      ],
      force: true
    )

    puts "Created feature branch #{branch_name} with #{NUM_COMMITS_PER_MR} commits"
  rescue Gitlab::Git::CommandError => e
    puts "Failed to create feature branch #{branch_name}, error: #{e.message}"
    exit(1)
  end

  def create_large_merge_request_with_discussions
    existing_mr = @project.merge_requests.find_by(source_branch: LARGE_MR_BRANCH) # rubocop:disable CodeReuse/ActiveRecord -- allowed in data seeder scripts:warn
    if existing_mr
      puts 'Large test seed merge request already exists'
      return
    end

    create_large_feature_branch_with_commits

    merge_request = create(:merge_request,
      title: 'Add large test seed feature with substantial changes',
      description: 'This MR simulates a realistic merge request with a large diff, ' \
        'multiple sizeable commits, and discussion threads for CPT load testing.',
      source_project: @project,
      target_project: @project,
      source_branch: LARGE_MR_BRANCH,
      target_branch: @project.default_branch || 'main',
      author: @user
    )
    puts 'Created large merge request'

    seed_discussions_for_merge_request(merge_request)
  end

  def create_large_feature_branch_with_commits
    if @project.repository.branch_exists?(LARGE_MR_BRANCH)
      puts "Feature branch #{LARGE_MR_BRANCH} already exists"
      return
    end

    LARGE_MR_COMMITS.times do |commit_index|
      step = commit_index + 1
      @project.repository.raw_repository.commit_files(
        system_user,
        branch_name: LARGE_MR_BRANCH,
        start_branch_name: step == 1 ? default_branch : nil,
        message: "Expand large test seed feature - part #{step}/#{LARGE_MR_COMMITS}",
        actions: [
          {
            action: step == 1 ? :create : :update,
            file_path: LARGE_MR_FILE,
            content: large_feature_file_content(step)
          }
        ],
        force: true
      )
    end

    puts "Created feature branch #{LARGE_MR_BRANCH} with #{LARGE_MR_COMMITS} sizeable commits"
  rescue Gitlab::Git::CommandError => e
    puts "Failed to create feature branch #{LARGE_MR_BRANCH}, error: #{e.message}"
    exit(1)
  end

  # Cumulative content: each step's commit replaces the whole file, so the diff grows per commit.
  def large_feature_file_content(up_to_step)
    classes = (1..up_to_step).map do |step|
      <<~RUBY
        class LargeTestSeedFeatureStep#{step}
          def initialize(name)
            @name = name
          end

          def process
            # Step #{step}: nontrivial transformation to simulate a real code change
            @name.to_s.chars.each_with_index.map { |char, index| char * ((index % 5) + 1) }.join
          end

          def summary
            "Processed \#{@name} at step #{step}"
          end
        end
      RUBY
    end

    "# frozen_string_literal: true\n\n#{classes.join("\n")}"
  end

  def seed_discussions_for_merge_request(merge_request)
    if merge_request.notes.any?
      puts 'Discussions already exist for large merge request'
      return
    end

    thread_starters = [
      { comment: 'This adds quite a bit of complexity in one file. Have we considered ' \
          'splitting LargeTestSeedFeatureStep classes into smaller units?',
        reply: 'Good point, will follow up in a separate MR.' },
      { comment: 'The `process` method name doesn\'t convey what transformation happens here ' \
          '- could we rename it to something more descriptive?',
        reply: 'Agreed, renaming in the next revision.' }
    ]

    thread_starters.each do |thread|
      discussion_note = create(:discussion_note_on_merge_request,
        noteable: merge_request,
        project: @project,
        author: @user,
        note: thread[:comment]
      )

      create(:note_on_merge_request,
        noteable: merge_request,
        project: @project,
        author: @user,
        note: thread[:reply],
        in_reply_to: discussion_note
      )
    end

    isolated_comments = [
      'LGTM overall, just a couple of style nits above.',
      'Pipeline passed, thanks for the quick turnaround!',
      'Nice work on the test coverage here.'
    ]

    isolated_comments.each do |comment|
      create(:note_on_merge_request,
        noteable: merge_request,
        project: @project,
        author: @user,
        note: comment
      )
    end

    puts "Seeded #{thread_starters.size} discussion threads and #{isolated_comments.size} isolated comments"
  end
end
