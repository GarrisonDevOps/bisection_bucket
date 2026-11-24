# frozen_string_literal: true

# rubocop:disable CodeReuse/ActiveRecord -- Seeder utility whose purpose is to create and look up records directly
module Gitlab
  module Seeders
    module Geo
      # Seeds one real Upload into each partition of the partitioned `uploads`
      # table, so Geo replication/verification of the per-partition upload
      # replicators (epic https://gitlab.com/groups/gitlab-org/-/work_items/20933)
      # can be exercised on GDK and on a production-like environment such as staging-ref.
      #
      # Dependency-free by design: no FactoryBot. Each Upload row is created as
      # a side effect of assigning a file to a model's real CarrierWave mount
      # and saving it. PostgreSQL routes the row to the correct partition by
      # `model_type` (= model.class.base_class.name), and Upload#ensure_sharding_key
      # copies the sharding key from the parent. The three import/export holders
      # have no belongs_to that sets project_id in memory, so we set it explicitly.
      #
      # Records are created off an existing project (reused, not created) to keep
      # the parent chains shallow and to avoid polluting the environment with new
      # organizations. Leaf records created here are tagged with SEED_MARKER so
      # they can be found and cleaned up later.
      #
      # Usage:
      #   Gitlab::Seeders::Geo::UploadPartitions.new(project).seed!
      class UploadPartitions
        SEED_MARKER = 'geo-seed'
        ROCKET_JPG = Rails.root.join('db/fixtures/development/rocket.jpg')
        HEART_PNG = Rails.root.join('db/fixtures/development/heart.png')

        # [label, expected model_type, recipe method]
        RECIPES = [
          ['Project (project_uploads)', 'Project', :seed_project],
          ['User (user_uploads)', 'User', :seed_user],
          ['Group (namespace_uploads)', 'Namespace', :seed_group],
          ['Achievement (achievement_uploads)', 'Achievements::Achievement', :seed_achievement],
          ['Topic (project_topic_uploads)', 'Projects::Topic', :seed_topic],
          ['OrganizationDetail (organization_detail_uploads)', 'Organizations::OrganizationDetail',
            :seed_organization_detail],
          ['Appearance (appearance_uploads)', 'Appearance', :seed_appearance],
          ['AbuseReport (abuse_report_uploads)', 'AbuseReport', :seed_abuse_report],
          ['AlertManagement::MetricImage (alert_management_alert_metric_image_uploads)',
            'AlertManagement::MetricImage', :seed_alert_metric_image],
          ['IssuableMetricImage (issuable_metric_image_uploads)', 'IssuableMetricImage',
            :seed_issuable_metric_image],
          ['PersonalSnippet (snippet_uploads)', 'Snippet', :seed_personal_snippet],
          ['DesignManagement::Action (design_management_action_uploads)', 'DesignManagement::Action',
            :seed_design_action],
          ['UserPermissionExportUpload (user_permission_export_upload_uploads)', 'UserPermissionExportUpload',
            :seed_user_permission_export_upload],
          ['ImportExportUpload (import_export_upload_uploads)', 'ImportExportUpload',
            :seed_import_export_upload],
          ['BulkImports::ExportUpload (bulk_import_export_upload_uploads)', 'BulkImports::ExportUpload',
            :seed_bulk_import_export_upload],
          ['Projects::ImportExport::RelationExportUpload (project_import_export_relation_export_upload_uploads)',
            'Projects::ImportExport::RelationExportUpload', :seed_relation_export_upload],
          ['Vulnerabilities::ArchiveExport (vulnerability_archive_export_uploads)',
            'Vulnerabilities::ArchiveExport', :seed_vulnerability_archive_export],
          ['Vulnerabilities::Export (vulnerability_export_uploads)', 'Vulnerabilities::Export',
            :seed_vulnerability_export],
          ['Vulnerabilities::Export::Part (vulnerability_export_part_uploads)', 'Vulnerabilities::Export::Part',
            :seed_vulnerability_export_part],
          ['Vulnerabilities::Remediation (vulnerability_remediation_uploads)', 'Vulnerabilities::Remediation',
            :seed_vulnerability_remediation],
          ['Dependencies::DependencyListExport (dependency_list_export_uploads)',
            'Dependencies::DependencyListExport', :seed_dependency_list_export],
          ['Dependencies::DependencyListExport::Part (dependency_list_export_part_uploads)',
            'Dependencies::DependencyListExport::Part', :seed_dependency_list_export_part]
        ].freeze

        def initialize(project)
          @project = project
          @group = project.group
          @user = project.first_owner || User.first
          @organization = project.organization
          @model_type_status = Hash.new(:failed)
        end

        def seed!(count: 1)
          log "Seeding upload partitions off project '#{project.full_path}' (count: #{count})"

          count.times do
            RECIPES.each { |label, model_type, recipe| attempt(label, model_type, recipe) }
          end

          report
        end

        private

        attr_reader :project, :group, :user, :organization

        def attempt(label, model_type, recipe)
          method(recipe).call
          @model_type_status[model_type] = :ok
          log "  OK   #{label}"
        rescue StandardError => e
          log "  FAIL #{label}: #{e.class}: #{e.message}"
        end

        # The next six models all mount `avatar` the same way, so assigning it
        # directly and saving is enough for PostgreSQL to route the row into
        # each one's partition.

        def seed_project
          project.avatar = image
          project.save!
        end

        def seed_user
          user.avatar = image
          user.save!
        end

        def seed_group
          raise "project '#{project.full_path}' is not in a Group namespace" unless group.is_a?(::Group)

          group.avatar = image
          group.save!
        end

        def seed_achievement
          achievement = ::Achievements::Achievement.new(
            namespace: group || project.project_namespace,
            name: "#{SEED_MARKER}-achievement-#{unique}")
          achievement.avatar = image
          achievement.save!
        end

        def seed_topic
          topic = ::Projects::Topic.new(
            organization: organization,
            name: "#{SEED_MARKER}-topic-#{unique}",
            title: "#{SEED_MARKER} topic #{unique}")
          topic.avatar = image
          topic.save!
        end

        def seed_organization_detail
          detail = organization.organization_detail
          detail.avatar = image
          detail.save!
        end

        # Appearance is a singleton, reused across seed runs rather than created
        # fresh, and mounts both `logo` and `favicon`. Assigning both here
        # intentionally creates two Upload rows for this one partition, to
        # exercise both mounts in a single call.

        def seed_appearance
          appearance = ::Appearance.current_without_cache || ::Appearance.create!(
            title: "#{SEED_MARKER} appearance", description: 'Seeded appearance')
          appearance.logo = image
          appearance.favicon = png
          appearance.save!
        end

        # AbuseReport lives on the main database and mounts its file field
        # directly, unlike the metric-image family below, which needs the
        # object-storage workaround.

        def seed_abuse_report
          report = ::AbuseReport.find_or_initialize_by(reporter: user, user: user, category: :spam)
          report.organization = organization
          report.message = "#{SEED_MARKER} abuse report"
          report.screenshot = png
          report.save!
        end

        # AlertManagement::MetricImage and IssuableMetricImage default to object
        # storage, which would need real bucket configuration to work. Forcing
        # LOCAL keeps seeding dependency-free.

        def seed_alert_metric_image
          alert = ::AlertManagement::Alert.create!(
            project: project, title: "#{SEED_MARKER} alert", started_at: Time.current)
          metric_image = ::AlertManagement::MetricImage.new(alert: alert, project: project)
          metric_image.file_store = ObjectStorage::Store::LOCAL
          metric_image.file = png
          metric_image.save!
        end

        def seed_issuable_metric_image
          metric_image = ::IssuableMetricImage.new(issue: issue)
          metric_image.file_store = ObjectStorage::Store::LOCAL
          metric_image.file = png
          metric_image.save!
        end

        # PersonalSnippet has no mountable uploader field of its own, so
        # UploadService is used instead, mirroring the same attach-and-create
        # flow the real upload endpoint uses.

        def seed_personal_snippet
          snippet = ::PersonalSnippet.create!(
            author: user, organization: organization,
            title: "#{SEED_MARKER} snippet", file_name: 'seed.txt', content: 'seeded content')
          ::UploadService.new(snippet, image, ::PersonalFileUploader).execute
        end

        # DesignManagement::Action has the deepest parent chain of any recipe
        # here (design and version records must exist first), and its image
        # mount requires ImageMagick to process the file.

        def seed_design_action
          namespace = project.project_namespace
          design = ::DesignManagement::Design.create!(
            project: project, issue: issue, namespace: namespace,
            filename: "#{SEED_MARKER}-#{unique}.png")

          version = ::DesignManagement::Version.new(
            sha: SecureRandom.hex(20), issue: issue, author: user, namespace: namespace)
          version.save!(validate: false)

          action = ::DesignManagement::Action.new(
            design: design, version: version, event: :creation, namespace: namespace)
          action.image_v432x230 = png
          action.save!
        end

        def seed_user_permission_export_upload
          # This model validates `file` length <= 255, and a mounted uploader's
          # #length returns the file's byte size, so the content must stay tiny.
          export = ::UserPermissionExportUpload.new(user: user, status: :created)
          export.file = string_file('seed', 'seed.csv', 'text/csv')
          export.save!
        end

        # The next six models live on the gitlab_sec database and mount `file`
        # directly, the same pattern as the main-database models above.

        def seed_vulnerability_archive_export
          export = ::Vulnerabilities::ArchiveExport.new(
            project: project, author: user,
            date_range: (5.days.ago.to_date..Date.current), format: :csv)
          export.file = image
          export.save!
        end

        def seed_vulnerability_export
          export = ::Vulnerabilities::Export.new(project: project, author: user, organization: organization)
          export.file = image
          export.save!
        end

        def seed_vulnerability_export_part
          part = ::Vulnerabilities::Export::Part.new(
            vulnerability_export: vulnerability_export_parent, organization: organization,
            start_id: 1, end_id: 1)
          part.file = image
          part.save!
        end

        def seed_vulnerability_remediation
          remediation = ::Vulnerabilities::Remediation.new(
            project: project, summary: "#{SEED_MARKER} remediation",
            checksum: Digest::SHA256.hexdigest(SecureRandom.hex(20)))
          remediation.file = diff
          remediation.save!
        end

        def seed_dependency_list_export
          export = ::Dependencies::DependencyListExport.new(
            project: project, author: user, status: :created, export_type: :dependency_list)
          export.file = image
          export.save!
        end

        def seed_dependency_list_export_part
          part = ::Dependencies::DependencyListExport::Part.new(
            dependency_list_export: dependency_list_export_parent, organization: organization,
            start_id: 0, end_id: 1)
          part.file = image
          part.save!
        end

        # These three models have no belongs_to that sets project_id in memory
        # (unlike the associations used above), so Upload#ensure_sharding_key
        # can't infer the sharding key on its own; set project_id explicitly.

        def seed_import_export_upload
          upload = ::ImportExportUpload.new(project: project, user: user)
          upload.export_file = targz
          upload.save!
        end

        def seed_bulk_import_export_upload
          bulk_export = ::BulkImports::Export.find_or_create_by!(project: project, user: user, relation: 'labels')
          upload = ::BulkImports::ExportUpload.find_or_initialize_by(export: bulk_export)
          upload.project_id = project.id
          upload.export_file = targz
          upload.save!
        end

        def seed_relation_export_upload
          job = ::ProjectExportJob.create!(project: project, user: user, jid: SecureRandom.hex(8))
          relation_export = ::Projects::ImportExport::RelationExport.create!(
            project_export_job: job, relation: 'labels')
          upload = ::Projects::ImportExport::RelationExportUpload.new(
            relation_export: relation_export, project: project)
          upload.export_file = targz
          upload.save!
        end

        # --- Shared parents / fixtures -----------------------------------------

        def issue
          @issue ||= project.issues.first ||
            ::Issue.create!(project: project, title: "#{SEED_MARKER} issue", author: user)
        end

        def vulnerability_export_parent
          @vulnerability_export_parent ||= ::Vulnerabilities::Export.create!(
            project: project, author: user, organization: organization)
        end

        def dependency_list_export_parent
          @dependency_list_export_parent ||= ::Dependencies::DependencyListExport.create!(
            project: project, author: user, status: :created, export_type: :dependency_list)
        end

        # Build in-memory files with short, controlled names. We read the fixture
        # bytes rather than handing CarrierWave the fixture File itself, because
        # some uploaders (AttachmentUploader, FaviconUploader) MOVE their source
        # into storage; reading bytes leaves the tracked fixtures untouched.

        def image
          string_file(File.binread(ROCKET_JPG), 'seed.jpg', 'image/jpeg')
        end

        def png
          string_file(File.binread(HEART_PNG), 'seed.png', 'image/png')
        end

        def targz
          string_file("seed export\n", 'seed.tar.gz', 'application/gzip')
        end

        def diff
          string_file("--- a\n+++ b\n@@ -0,0 +1 @@\n+seed\n", 'seed.diff', 'text/plain')
        end

        def string_file(content, filename, content_type)
          CarrierWaveStringFile.new_file(file_content: content, filename: filename, content_type: content_type)
        end

        def unique
          SecureRandom.hex(4)
        end

        def upload_count(model_type)
          ::Upload.where(model_type: model_type).count
        end

        def report
          log "\nUpload counts by partition (model_type):"

          RECIPES.map { |_, model_type, _| model_type }.uniq.each do |model_type|
            log "  #{model_type}: #{status_marker(model_type)}"
          end
        end

        # Report the recipe outcome first, then the count. Driving the label off
        # the run status (not off upload_count, which includes pre-existing rows)
        # ensures a recipe that raised always shows FAILED, even when the
        # partition already held rows from earlier runs.
        def status_marker(model_type)
          return 'FAILED (see errors above)' unless @model_type_status[model_type] == :ok

          "#{upload_count(model_type)} row(s)"
        end

        def log(message)
          puts message
        end
      end
    end
  end
end
# rubocop:enable CodeReuse/ActiveRecord
