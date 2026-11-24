# frozen_string_literal: true

module SecretsManagement
  module RakeTask
    class Seed
      HIERARCHY = [
        { path: 'subgroup-a', children: [
          { path: 'subgroup-a1', projects: %w[project-a1a] }
        ], projects: %w[project-a1 project-a2] },
        { path: 'subgroup-b', children: [
          { path: 'subgroup-b1', projects: %w[project-b1x] }
        ], projects: %w[project-b1] }
      ].freeze

      TOP_LEVEL_PROJECTS = %w[project-top1].freeze

      GROUP_SECRET_SETS = [
        [%w[DB_PASSWORD s3cret-db-pass], %w[API_KEY api-key-123], %w[AUTH_TOKEN token-abc]],
        [%w[SECRET_1 val-1], %w[SECRET_2 val-2]],
        [%w[SECRET_1 val-1], %w[SECRET_2 val-2], %w[SECRET_3 val-3]]
      ].freeze

      PROJECT_SECRET_POOL = [
        %w[DB_URL postgres://host/db],
        %w[REDIS_URL redis://host],
        %w[SECRET_KEY super-secret],
        %w[DEPLOY_TOKEN deploy-tok-123]
      ].freeze

      def initialize(root_namespace_id)
        @root_namespace_id = root_namespace_id
        @groups = []
        @projects = []
      end

      def execute
        validate!
        enroll!

        puts header
        Labkit::Correlation::CorrelationId.use_id("seed-secrets-#{SecureRandom.hex(8)}") do
          create_hierarchy
          provision_secrets_managers
          create_secrets
          print_summary
        end
        puts "\nDone."
      end

      private

      def validate!
        @root = Namespace.find_by(id: @root_namespace_id) # rubocop:disable CodeReuse/ActiveRecord -- rake task lookup by ID
        abort "ERROR: Namespace #{@root_namespace_id} not found" unless @root
        abort "ERROR: Namespace #{@root.full_path} is not a group" unless @root.is_a?(Group)

        @user = User.find_by_username('root') || User.admins.first
        abort "ERROR: No admin user found" unless @user

        @root.add_owner(@user) unless @root.member?(@user)
      end

      # Dev-only routing: when GITLAB_SIMULATE_SAAS=1, mimic .com behavior and
      # enroll the root namespace; otherwise (the common GDK path) enroll the
      # instance.
      def enroll!
        if ::Gitlab.simulate_com?
          enroll_namespace!
        else
          enroll_instance!
        end
      end

      def enroll_namespace!
        result = ::SecretsManagement::NamespaceEnrollmentService.new(@root, current_user: @user).enroll

        if result.success?
          puts "Enrolled namespace: #{@root.full_path}"
        elsif result.message == 'Namespace is already enrolled.'
          puts "[skip] Namespace already enrolled: #{@root.full_path}"
        else
          abort "ERROR: Could not enroll namespace #{@root.full_path}: #{result.message}"
        end
      end

      def enroll_instance!
        result = ::SecretsManagement::InstanceEnrollmentService.new(current_user: @user).enroll

        if result.success?
          puts "Enrolled instance"
        elsif result.message == 'Instance is already enrolled.'
          puts "[skip] Instance already enrolled"
        else
          abort "ERROR: Could not enroll instance: #{result.message}"
        end
      end

      def header
        <<~HEADER
          #{'=' * 60}
          Secrets Manager Seed
          #{'=' * 60}
          Root namespace: #{@root.full_path} (id: #{@root.id})
          User: #{@user.username} (id: #{@user.id})
        HEADER
      end

      def create_hierarchy
        puts "\n--- Creating hierarchy ---"

        @groups << @root

        TOP_LEVEL_PROJECTS.each { |p| @projects << find_or_create_project(@root, p) }

        HIERARCHY.each { |node| create_subtree(@root, node) }
      end

      def create_subtree(parent, node)
        group = find_or_create_group(parent, node[:path])
        @groups << group

        (node[:projects] || []).each { |p| @projects << find_or_create_project(group, p) }
        (node[:children] || []).each { |child| create_subtree(group, child) }
      end

      def find_or_create_group(parent, path)
        full = "#{parent.full_path}/#{path}"
        existing = Group.find_by_full_path(full)
        return existing if existing

        result = Groups::CreateService.new(@user, {
          name: path, path: path, parent_id: parent.id,
          visibility_level: Gitlab::VisibilityLevel::PRIVATE,
          organization_id: parent.organization_id
        }).execute

        group = result.is_a?(ServiceResponse) ? result.payload[:group] : result
        abort "  FATAL: Could not create group #{full}" unless group&.persisted?

        puts "  Created group: #{group.full_path} (id: #{group.id})"
        group
      end

      def find_or_create_project(namespace, path)
        full = "#{namespace.full_path}/#{path}"
        existing = Project.find_by_full_path(full)
        return existing if existing

        project = Projects::CreateService.new(@user, {
          name: path, path: path, namespace_id: namespace.id,
          visibility_level: Gitlab::VisibilityLevel::PRIVATE
        }).execute

        unless project.persisted?
          abort "  FATAL: Could not create project #{full}: #{project.errors.full_messages.join(', ')}"
        end

        puts "  Created project: #{project.full_path} (id: #{project.id})"
        project
      end

      def provision_secrets_managers
        puts "\n--- Provisioning secrets managers ---"

        @groups.each { |g| provision_group_sm(g) }
        @projects.each { |p| provision_project_sm(p) }
      end

      def provision_group_sm(group)
        if group.secrets_manager&.active?
          puts "  [skip] Group SM already active: #{group.full_path}"
          return
        end

        # Create the record directly instead of using InitializeService, which
        # enqueues a Sidekiq worker that would race with our synchronous provision call.
        sm = group.secrets_manager || GroupSecretsManager.create!(group: group)
        prov = GroupSecretsManagers::ProvisionService.new(sm, @user).execute
        sm.reset

        if prov.success? && sm.active?
          puts "  Provisioned group SM: #{group.full_path} (#{sm.root_namespace_path}/#{sm.group_path})"
        else
          warn "  ERROR provision group SM #{group.full_path}: #{prov.message}"
        end
      end

      def provision_project_sm(project)
        if project.secrets_manager&.active?
          puts "  [skip] Project SM already active: #{project.full_path}"
          return
        end

        # Create the record directly instead of using InitializeService, which
        # enqueues a Sidekiq worker that would race with our synchronous provision call.
        sm = project.secrets_manager || ProjectSecretsManager.create!(project: project)
        prov = ProjectSecretsManagers::ProvisionService.new(sm, @user).execute
        sm.reset

        if prov.success? && sm.active?
          puts "  Provisioned project SM: #{project.full_path} (#{sm.namespace_path}/#{sm.project_path})"
        else
          warn "  ERROR provision project SM #{project.full_path}: #{prov.message}"
        end
      end

      def create_secrets
        puts "\n--- Creating secrets ---"

        @groups.each_with_index do |group, i|
          secrets = prefixed_secrets(
            group.path.upcase.tr('-', '_'),
            GROUP_SECRET_SETS[i % GROUP_SECRET_SETS.size]
          )
          create_group_secrets(group, secrets)
        end

        @projects.each_with_index do |project, i|
          count = (i % PROJECT_SECRET_POOL.size) + 1
          secrets = prefixed_secrets(
            project.path.upcase.tr('-', '_'),
            PROJECT_SECRET_POOL.first(count)
          )
          create_project_secrets(project, secrets)
        end
      end

      def prefixed_secrets(prefix, secrets)
        secrets.map { |name, value| ["#{prefix}_#{name}", "#{prefix.downcase}-#{value}"] }
      end

      def create_group_secrets(group, secrets)
        return unless group.secrets_manager&.active?

        created = secrets.count do |name, value|
          result = GroupSecrets::CreateService.new(group, @user).execute(
            name: name, value: value, description: "Seeded: #{name}", environment: '*', protected: false
          )
          result.success?
        end
        puts "  #{created}/#{secrets.size} group secrets for #{group.full_path}"
      end

      def create_project_secrets(project, secrets)
        return unless project.secrets_manager&.active?

        created = secrets.count do |name, value|
          result = ProjectSecrets::CreateService.new(project, @user).execute(
            name: name, value: value, description: "Seeded: #{name}", environment: '*', branch: '*'
          )
          result.success?
        end
        puts "  #{created}/#{secrets.size} project secrets for #{project.full_path}"
      end

      def print_summary
        puts "\n--- Summary ---"

        total_group = 0
        total_project = 0

        @groups.each do |g|
          next unless g.secrets_manager&.active?

          result = GroupSecrets::ListService.new(g, @user).execute
          count = result.success? ? result.payload[:secrets].size : 0
          total_group += count
          puts "  GROUP   #{g.full_path}: #{count} secrets"
        end

        @projects.each do |p|
          next unless p.secrets_manager&.active?

          result = ProjectSecrets::ListService.new(p, @user).execute
          count = result.success? ? result.payload[:secrets].size : 0
          total_project += count
          puts "  PROJECT #{p.full_path}: #{count} secrets"
        end

        puts "\n  Group secrets:   #{total_group}"
        puts "  Project secrets: #{total_project}"
        puts "  TOTAL:           #{total_group + total_project}"
      end
    end
  end
end
