# frozen_string_literal: true

namespace :gitlab do
  namespace :seed do
    def projects_from_args(args)
      full_path = args.project_full_path

      if full_path
        project = Project.find_by_full_path(full_path)

        unless project
          error_message = "Project '#{full_path}' does not exist!"
          potential_projects = Project.search(full_path)

          if potential_projects.present?
            error_message += " Did you mean '#{potential_projects.first.full_path}'?"
          end

          puts Rainbow(error_message).red
          exit 1
        end

        [project]
      else
        scope = Project.respond_to?(:not_mass_generated) ? Project.not_mass_generated : Project
        scope.find_each
      end
    end

    desc "GitLab | Seed | Seeds issues"
    task :issues, [:project_full_path, :backfill_weeks, :average_issues_per_week] => :environment do |t, args|
      args.with_defaults(backfill_weeks: 5, average_issues_per_week: 2)

      projects = projects_from_args(args)

      projects.each do |project|
        puts "\nSeeding issues for the '#{project.full_path}' project"
        seeder = Quality::Seeders::Issues.new(project: project)
        issues_created = seeder.seed(backfill_weeks: args.backfill_weeks.to_i,
          average_issues_per_week: args.average_issues_per_week.to_i)
        puts "\n#{issues_created} issues created!"
      end
    end

    task :epics, [:group_full_path, :backfill_weeks, :average_issues_per_week] => :environment do |t, args|
      args.with_defaults(backfill_weeks: 5, average_issues_per_week: 2)

      groups =
        if args.group_full_path
          group = Group.find_by_full_path(args.group_full_path)

          unless group
            error_message = "Group '#{args.group_full_path}' does not exist!"
            potential_groups = Group.search(args.group_full_path)

            if potential_groups.present?
              error_message += " Did you mean '#{potential_groups.first.full_path}'?"
            end

            puts Rainbow(error_message).red
            exit 1
          end

          [group]
        else
          Group.not_mass_generated.find_each
        end

      groups.each do |group|
        puts "\nSeeding epics for the '#{group.full_path}' group"
        seeder = Quality::Seeders::Epics.new(group: group)
        epics = seeder.seed(
          backfill_weeks: args.backfill_weeks.to_i,
          average_issues_per_week: args.average_issues_per_week.to_i
        )
        puts "\n#{epics} epics created!"
      end
    end

    desc "GitLab | Seed | Seed a project with vulnerabilities"
    task :vulnerabilities, [:project_full_path] => :environment do |t, args|
      projects = projects_from_args(args)

      projects.each do |project|
        puts "\nSeeding vulnerabilities for the '#{project.full_path}' project"
        seeder = Quality::Seeders::Vulnerabilities.new(project)
        seeder.seed!
        puts "\nDone."
      end
    end

    desc "GitLab | Seed | Seed a new group with dependencies"
    task :dependencies, [] => :environment do |t, args|
      puts "\nSeeding a new group with dependencies"
      seeder = Quality::Seeders::Dependencies.new
      seeder.seed!
      puts "\nDone."
    end

    # `db/docs/` also holds views, deleted tables and background migrations, and the dictionary is
    # the authority on which names are tables. Its default scope covers only tables, so anything
    # else returns nil here and is ignored.
    def dictionary_table_entries(names)
      names.filter_map { |name| Gitlab::Database::Dictionary.entry(name) }
    end

    # Every decomposed database holds the full schema, so counting a `gitlab_ci` table on the main
    # connection reads an always-empty copy of it.
    def base_model_for_entry(entry)
      Gitlab::Database.schemas_to_base_models[entry.gitlab_schema]&.first
    end

    desc "GitLab | Seed | Report seed coverage for tables added since a git ref"
    task :coverage_report, [:base_ref] => :environment do |t, args|
      require_relative "../../../tooling/quality/added_tables"
      require_relative "../../../tooling/quality/fixture_coverage"

      # Only merged-results pipelines expose the target branch tip, and it is the only safe base:
      # the merge base diffs in whatever master gained since the branch point, which for a branch
      # that already contains master means other merge requests' tables.
      base_ref = args.base_ref.presence || ENV["CI_MERGE_REQUEST_TARGET_BRANCH_SHA"].presence
      next puts "\nNo target branch SHA, skipping the fixture coverage report" unless base_ref

      begin
        added = Quality::AddedTables.new(base_ref).entry_names
      rescue Quality::AddedTables::UnreadableBaseRef => e
        next puts "\nCannot report fixture coverage: #{e.message}"
      end

      entries = dictionary_table_entries(added)
      next puts "\nNo new tables in this diff, skipping the fixture coverage report" if entries.empty?

      puts "\nFixture coverage for #{entries.size} newly added table(s)"

      unseeded = []

      entries.group_by { |entry| base_model_for_entry(entry) }.each do |base_model, group|
        tables = group.map(&:table_name)
        next puts "  #{tables.join(', ')}: no connection for gitlab_schema, cannot check" unless base_model

        coverage = Quality::FixtureCoverage.new(tables, connection: base_model.connection)
        coverage.findings.each do |finding|
          puts "  #{finding.table}: #{finding.summary}"
          unseeded << finding.table if finding.unseeded?
        end
      end

      next if unseeded.empty?

      abort "\nNo seed data for #{unseeded.join(', ')}. Add a fixture in db/fixtures/development/ " \
        "so that migrations touching it are exercised by db:migrate:multi-version-upgrade."
    end

    desc "GitLab | Seed | Report which value classes the seeded rows cover, per column"
    task :value_class_report, [:tables] => :environment do |t, args|
      require_relative "../../../tooling/quality/value_class_coverage"

      # Counting every class on every column scans each table, so keep it away from a real install.
      next puts "\nThis report only runs in development and test" unless Gitlab.dev_or_test_env?

      # Rake splits `[a,b]` into separate arguments, so the rest of the list arrives in `extras`.
      names = [args.tables, *args.extras].map { |name| name.to_s.strip }.reject(&:empty?)
      entries = names.any? ? dictionary_table_entries(names) : Gitlab::Database::Dictionary.entries.to_a
      next puts "\nNo tables to report on" if entries.empty?

      puts "\nValue class coverage for #{entries.size} table(s)"

      entries.group_by { |entry| base_model_for_entry(entry) }.each do |base_model, group|
        tables = group.map(&:table_name)
        next puts "  #{tables.join(', ')}: no connection for gitlab_schema, cannot check" unless base_model

        coverage = Quality::ValueClassCoverage.new(tables, connection: base_model.connection)
        reportable = coverage.findings.reject(&:complete?)
        # Naming tables asks what their fixture should produce, so the unseeded ones are the
        # answer. A sweep of everything would instead be buried under the hundreds holding no
        # rows, which the coverage report already flags.
        reportable = reportable.reject(&:unseeded?) unless names.any?

        reportable.group_by(&:table).each do |table, findings|
          puts "  #{table}"
          findings.each { |finding| puts "    #{finding.summary}" }
        end
      end
    end

    desc "GitLab | Seed | Write value class coverage totals as an OpenMetrics report"
    task value_class_metrics: :environment do
      next puts "\nThis report only runs in development and test" unless Gitlab.dev_or_test_env?

      metrics_path = ENV.fetch('METRICS_FILE', 'metrics.txt')
      report_path = ENV.fetch('FIXTURE_COVERAGE_FILE', 'fixture_coverage.txt')

      begin
        # Emptied up front so a failure part way through cannot leave a stale report behind, and
        # so the rescue never has to overwrite one that was already written correctly.
        File.write(metrics_path, '')
        File.write(report_path, '')

        require_relative "../../../tooling/quality/value_class_coverage"

        findings = Gitlab::Database::Dictionary.entries.to_a
          .group_by { |entry| base_model_for_entry(entry) }
          .flat_map do |base_model, group|
            unless base_model
              puts "  no connection for #{group.map(&:gitlab_schema).uniq.sort.join(', ')}, " \
                "cannot check #{group.size} table(s)"
              next []
            end

            Quality::ValueClassCoverage.new(group.map(&:table_name), connection: base_model.connection).findings
          end

        seeded, unseeded = findings.partition(&:seeded)
        gaps = seeded.reject(&:complete?)

        # Every checked column, not only the gapped ones: what a column covers today is what says
        # whether a later run lost it, and an empty table's columns would otherwise vanish entirely.
        report = findings.map do |finding|
          state = finding.seeded ? 'seeded' : 'empty'
          covered = finding.covered.presence&.join(',') || '-'
          missing = finding.missing.presence&.join(',') || '-'

          "#{finding.table}.#{finding.column} #{finding.type} #{state} #{covered} #{missing}\n"
        end

        # A table with no rows misses every class on every column, so counting its columns would bury
        # the ones whose fixture exists but leaves a shape untested. Empty tables are their own metric.
        metrics = {
          'dev_fixtures_tables_checked' => findings.map(&:table).uniq.size,
          'dev_fixtures_tables_empty' => unseeded.map(&:table).uniq.size,
          'dev_fixtures_columns_checked' => seeded.size,
          'dev_fixtures_columns_with_gaps' => gaps.size
        }

        File.write(metrics_path, metrics.map { |name, value| "# TYPE #{name} gauge\n#{name} #{value}\n" }.join)
        # Sorted so a diff between two runs shows a changed column rather than a changed order.
        File.write(report_path, report.sort.join)

        puts "\nFixture coverage metrics written to #{metrics_path}"
        metrics.each { |name, value| puts "  #{name} #{value}" }
      rescue StandardError, ScriptError => e # LoadError/SyntaxError from a broken install are not StandardErrors
        # Seeding and the coverage check are what this job exists for, so a measurement that cannot
        # run leaves empty reports rather than failing the job or publishing a zero.
        puts "\nFixture coverage metrics skipped: #{e.class}: #{e.message}"
      end
    end
  end
end
