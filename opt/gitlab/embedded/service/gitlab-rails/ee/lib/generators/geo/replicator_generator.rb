# frozen_string_literal: true

require 'rails/generators/named_base'

module Geo
  # Shared base for the Geo SSF (self-service framework) replicator generators.
  #
  # Holds the orchestration, framework-file patching, derived-doc regeneration and the
  # per-replicable file creation common to every replicable type. Concrete generators (e.g.
  # BlobReplicatorGenerator) subclass it and override the per-type hooks (create_model,
  # create_type_specific_files, replicator_model_template, worker_spec_anchors,
  # extra_framework_patches, ...).
  class ReplicatorGenerator < Rails::Generators::NamedBase
    source_root File.expand_path('templates', __dir__)

    # Abstract base: hide it from `rails g` so only the concrete subclasses are listed.
    hide!

    desc 'Shared base for the Geo SSF replicator generators (not invoked directly).'

    MIGRATION_VERSION = '2.3'
    VALID_SHARDING_KEYS = %w[project_id namespace_id organization_id uploaded_by_user_id].freeze
    FEATURE_ISSUE_URL = 'https://gitlab.com/gitlab-org/gitlab/-/issues/589925'
    GEO_STATUS_ANCHOR = 'git_fetch_event_count_weekly'

    # Doc/metrics artifacts regenerated from the generated code after the files are written.
    POST_GENERATION_TASKS = [
      'tooling/bin/gettext_extractor locale/gitlab.pot',
      'bundle exec rake geo:dev:ssf_metrics',
      'bundle exec rake gitlab:db:dictionary:generate',
      'bundle exec rake gitlab:graphql:docs:compile',
      'bundle exec rake gitlab:graphql:generate_all_introspection_schemas',
      'bundle exec rake gitlab:openapi:v3:generate'
    ].freeze

    class_option :table_name, type: :string, required: true,
      desc: 'Database table name (e.g. abuse_report_uploads)'
    class_option :sharding_key, type: :array, required: false, banner: 'project_id namespace_id',
      desc: "Sharding key column(s). One of: #{VALID_SHARDING_KEYS.join(', ')}. " \
        'Required unless the replicable has no sharding key (see --no-sharding-key).'
    class_option :milestone, type: :string, required: true,
      desc: 'Milestone for this feature (e.g. 18.10)'
    class_option :model_class, type: :string,
      desc: 'Ruby model class name (required unless --upload-partition; then defaults to the ' \
        'CamelCase of NAME)'
    class_option :skip_post_generate, type: :boolean, default: false,
      desc: 'Skip the post-generation rake tasks (gettext, SSF metrics, dictionary, GraphQL/' \
        'OpenAPI docs) and the RuboCop autocorrect of the generated files'
    class_option :only_post_generate, type: :boolean, default: false,
      desc: 'Post-rebase mode: skip new-file creation, but re-apply the (idempotent) framework ' \
        'patches and re-run the derived-doc regeneration rake tasks (and the RuboCop autocorrect)'

    # NamedBase provides the NAME argument plus file_name and class_name.

    def validate!
      errors = []
      errors << '--sharding-key must be provided' if sharding_key_missing?

      invalid = sharding_keys - VALID_SHARDING_KEYS
      unless invalid.empty?
        errors << "--sharding-key must be one of: #{VALID_SHARDING_KEYS.join(', ')} " \
          "(got invalid: #{invalid.join(', ')})"
      end

      errors << '--model-class is required' if model_class_required? && model_class.blank?

      errors << "NAME must be snake_case (got: #{file_name})" unless file_name.match?(/\A[a-z0-9_]+\z/)
      errors << "--table-name must be snake_case (got: #{table_name})" unless table_name.to_s.match?(/\A[a-z0-9_]+\z/)
      errors << "--milestone must be MAJOR.MINOR (got: #{milestone})" unless milestone.to_s.match?(/\A\d+\.\d+\z/)

      if options[:model_class] && !options[:model_class].match?(/\A[A-Za-z0-9:]+\z/)
        errors << "--model-class must be a Ruby class name (got: #{options[:model_class]})"
      end

      if options[:only_post_generate] && options[:skip_post_generate]
        errors << '--only-post-generate cannot be combined with --skip-post-generate ' \
          '(there would be nothing left to do)'
      end

      errors.concat(extra_validation_errors)

      raise Thor::Error, errors.join("\n") unless errors.empty?
    end

    # In --only-post-generate mode the per-replicable files already exist (the branch is being
    # rebased), so skip new-file creation. The framework patches still run (they are idempotent) so
    # any reset/lost entries are re-applied, followed by the derived-doc regeneration.
    def create_files
      return if only_post_generate?

      create_model
      create_replicator
      create_registry_model
      create_state_model
      create_finder
      create_graphql
      create_feature_flags
      create_geo_registry_migration
      create_state_migration
      create_sharding_key_trigger_migrations
      create_dictionaries
      create_factories
      create_specs
      create_type_specific_files
    end

    # Runs in --only-post-generate too: every patch is idempotent, so this re-applies any entries
    # that were reset while resolving a rebase, without creating new files or migrations.
    def patch_framework_files
      patch_replicator_classes
      patch_geo_node_type
      patch_inflections
      patch_registries_shared_context
      patch_registries_spec
      patch_registry_consistency_worker_spec
      patch_geo_node_type_spec
      patch_registry_class_enum_spec
      patch_possible_types_json
      patch_geo_status_json('ee/spec/fixtures/api/schemas/public_api/v4/geo_node_status.json')
      patch_geo_status_json('ee/spec/fixtures/api/schemas/public_api/v4/geo_site_status.json')
      patch_geo_api_doc('doc/api/geo_nodes.md')
      patch_geo_api_doc('doc/api/geo_sites.md')
      patch_prometheus_metrics_doc

      extra_framework_patches
    end

    # Regenerate the derived docs/metrics from the generated code, then RuboCop-autocorrect the
    # generated and patched Ruby (templates aim to be clean; this is the safety net). Only runs
    # for a real repo generation; skipped in --pretend and in the generator test sandbox.
    def post_generate
      return if options[:pretend] || options[:skip_post_generate] || !generating_into_repo?

      POST_GENERATION_TASKS.each { |command| run(command) }

      autocorrect_generated_files
      print_next_steps
    end

    private

    def create_replicator
      template replicator_model_template, "ee/app/replicators/geo/#{file_name}_replicator.rb"
    end

    def create_registry_model
      template 'models/registry.rb.tt', "ee/app/models/geo/#{file_name}_registry.rb"
    end

    def create_state_model
      template 'models/state.rb.tt', "ee/app/models/geo/#{file_name}_state.rb"
    end

    # Default: the replicable wraps an existing domain model, so wire it as a Geo replicable in its
    # EE concern (ee/app/models/ee/<model>.rb). Subclasses that generate their own model (e.g. the
    # upload-partition blob) override this.
    def create_model
      path = model_ee_concern_path

      if File.exist?(destination_path(path))
        inject_model_wiring(path)
      else
        create_file path, model_ee_concern_content
      end
    end

    # Inject the Geo wiring into an existing EE concern using its conventional anchors. If the
    # anchors are absent we do not risk corrupting the file: print a paste-ready snippet instead.
    def inject_model_wiring(path)
      content = File.read(destination_path(path))
      return if content.include?("with_replicator ::Geo::#{replicator_class_name}")

      unless content.match?(/^\s*prepended do$/) && content.match?(/^\s*class_methods do$/)
        say_status(:todo, "#{path}: add Geo wiring manually:\n#{model_ee_concern_content}", :red)
        return
      end

      inject_into_file path, indent(model_prepended_wiring, 6), after: /^\s*prepended do\n/
      inject_into_file path, indent(model_class_methods_wiring, 6), after: /^\s*class_methods do\n/
    end

    def model_ee_concern_path
      "ee/app/models/ee/#{model_class.underscore}.rb"
    end

    def model_ee_concern_content
      inner = +"extend ActiveSupport::Concern\n\n"
      inner << "prepended do\n#{indent(model_prepended_wiring, 2)}end\n\n"
      inner << "class_methods do\n#{indent(model_class_methods_wiring, 2)}end\n"

      "# frozen_string_literal: true\n\n#{wrap_in_modules(['EE', *model_class.split('::')], inner)}"
    end

    # Wrap `body` in nested `module` declarations (outermost first), indenting two spaces per level.
    def wrap_in_modules(parts, body)
      parts.reverse.reduce(body) { |acc, part| "module #{part}\n#{indent(acc, 2)}end\n" }
    end

    def model_prepended_wiring
      base = <<~RUBY
        include ::Geo::ReplicableModel
        include ::Geo::VerifiableModel

        delegate(*::Geo::VerificationState::VERIFICATION_METHODS, to: :#{file_name}_state)

        with_replicator ::Geo::#{replicator_class_name}

        has_one :#{file_name}_state, autosave: false, inverse_of: :#{file_name},
          class_name: 'Geo::#{state_class_name}'

        # TODO: model-specific sharding-key scope. Some models scope through an association
        # (e.g. joins) instead of a direct column. Review before merging.
        #{scope_definition}

        def verification_state_object
          #{file_name}_state
        end
      RUBY

      extra = model_extra_prepended_methods
      extra.empty? ? base : "#{base}\n#{extra}"
    end

    # Extra instance methods for the prepended block (e.g. pool_repository for repository types).
    # Empty for the default flavor.
    def model_extra_prepended_methods
      ''
    end

    def model_class_methods_wiring
      <<~RUBY
        extend ::Gitlab::Utils::Override

        override :verification_state_model_key
        def verification_state_model_key
          :#{foreign_key_name}
        end

        override :verification_state_table_class
        def verification_state_table_class
          Geo::#{state_class_name}
        end

        # TODO: selective_sync_scope is model-specific. Review and consult a Geo expert if needed.
        override :selective_sync_scope
        def selective_sync_scope(node, **params)
        #{raw_selective_sync_scope_body}
        end
      RUBY
    end

    def create_finder
      template 'finder.rb.tt', "ee/app/finders/geo/#{file_name}_registry_finder.rb"
    end

    def create_graphql
      template 'graphql/resolver.rb.tt',
        "ee/app/graphql/resolvers/geo/#{file_name}_registries_resolver.rb"
      template 'graphql/type.rb.tt',
        "ee/app/graphql/types/geo/#{file_name}_registry_type.rb"
    end

    def create_feature_flags
      template 'feature_flags/replication.tt',
        "ee/config/feature_flags/ops/#{replication_feature_flag_name}.yml"
      template 'feature_flags/force_primary_checksumming.tt',
        "ee/config/feature_flags/ops/#{force_primary_checksumming_feature_name}.yml"
    end

    def create_geo_registry_migration
      template 'migrations/registry.rb.tt',
        "ee/db/geo/migrate/#{geo_migration_timestamp}_create_#{file_name}_registry.rb"
    end

    def create_state_migration
      template 'migrations/states.rb.tt',
        "db/migrate/#{state_timestamp}_create_#{file_name}_states.rb"
    end

    def create_sharding_key_trigger_migrations
      sharding_keys.each_with_index do |key, index|
        @current_sharding_key = key
        template 'migrations/sharding_key_trigger.rb.tt',
          "db/migrate/#{trigger_timestamp(index)}_add_#{file_name}_states_#{key}_sharding_key_trigger.rb"
      end
      @current_sharding_key = nil
    end

    def create_dictionaries
      template 'dictionaries/registry.tt', "ee/db/geo/docs/#{registry_table_name}.yml"
      template 'dictionaries/states.tt', "db/docs/#{state_table_name}.yml"
    end

    def create_factories
      template 'factories/registry.rb.tt', "ee/spec/factories/geo/#{file_name}_registry.rb"
      template 'factories/state.rb.tt', "ee/spec/factories/geo/#{file_name}_states.rb"
    end

    def create_specs
      template replicator_spec_template, "ee/spec/replicators/geo/#{file_name}_replicator_spec.rb"
      template 'specs/registry_spec.rb.tt', "ee/spec/models/geo/#{file_name}_registry_spec.rb"
      template 'specs/finder_spec.rb.tt', "ee/spec/finders/geo/#{file_name}_registry_finder_spec.rb"
      template 'specs/resolver_spec.rb.tt',
        "ee/spec/graphql/resolvers/geo/#{file_name}_registries_resolver_spec.rb"
      template 'specs/type_spec.rb.tt',
        "ee/spec/graphql/types/geo/#{file_name}_registry_type_spec.rb"
    end

    def only_post_generate?
      options[:only_post_generate]
    end

    def generating_into_repo?
      File.realpath(destination_root) == File.realpath(Rails.root.to_s)
    rescue Errno::ENOENT
      false
    end

    def autocorrect_generated_files
      files = touched_ruby_files
      return if files.empty?

      run("bundle exec rubocop --autocorrect --no-server #{files.join(' ')}")
    end

    # Generated + patched Ruby files, used as RuboCop autocorrect targets. Migration paths use
    # the memoized timestamps so they match what was written. Non-existent entries (e.g. skipped
    # patches) are filtered out.
    def touched_ruby_files
      files = [
        "ee/app/replicators/geo/#{file_name}_replicator.rb",
        "ee/app/models/geo/#{file_name}_registry.rb",
        "ee/app/models/geo/#{file_name}_state.rb",
        "ee/app/finders/geo/#{file_name}_registry_finder.rb",
        "ee/app/graphql/resolvers/geo/#{file_name}_registries_resolver.rb",
        "ee/app/graphql/types/geo/#{file_name}_registry_type.rb",
        "ee/spec/replicators/geo/#{file_name}_replicator_spec.rb",
        "ee/spec/models/geo/#{file_name}_registry_spec.rb",
        "ee/spec/finders/geo/#{file_name}_registry_finder_spec.rb",
        "ee/spec/graphql/resolvers/geo/#{file_name}_registries_resolver_spec.rb",
        "ee/spec/graphql/types/geo/#{file_name}_registry_type_spec.rb",
        "ee/spec/factories/geo/#{file_name}_registry.rb",
        "ee/spec/factories/geo/#{file_name}_states.rb",
        "ee/db/geo/migrate/#{geo_migration_timestamp}_create_#{file_name}_registry.rb",
        "db/migrate/#{state_timestamp}_create_#{file_name}_states.rb",
        # Patched framework files
        'ee/lib/gitlab/geo.rb',
        'ee/app/graphql/types/geo/geo_node_type.rb',
        'ee/spec/support/shared_contexts/graphql/geo/registries_shared_context.rb',
        'ee/spec/requests/api/graphql/geo/registries_spec.rb',
        'ee/spec/workers/geo/secondary/registry_consistency_worker_spec.rb',
        'ee/spec/graphql/types/geo/geo_node_type_spec.rb',
        'ee/spec/graphql/types/geo/registry_class_enum_spec.rb'
      ]

      files.concat(type_specific_ruby_files)

      sharding_keys.each_with_index do |key, index|
        files << "db/migrate/#{trigger_timestamp(index)}_add_#{file_name}_states_#{key}_sharding_key_trigger.rb"
      end

      files.select { |f| File.exist?(destination_path(f)) }
    end

    def print_next_steps
      say_status(:todo, 'Run migrations: bin/rake db:migrate:geo RAILS_ENV=test && bin/rake db:migrate', :yellow)
      say_status(:todo, 'Fill introduced_by_url/rollout_issue_url in the generated feature flags', :yellow)

      print_model_next_steps
    end

    # The default (wire-an-existing-model) flow needs manual follow-up on the model. Subclasses that
    # generate their own model (upload-partition) override this to skip it.
    def print_model_next_steps
      say_status(:todo, "Ensure #{model_class} has prepend_mod_with('#{model_class}') so the EE Geo " \
        "wiring loads", :yellow)
      say_status(:todo, "Review #{model_ee_concern_path}: the sharding-key scope and " \
        "selective_sync_scope are model-specific", :yellow)
      say_status(:todo, "Add verification_succeeded/verification_failed/:remote_store traits to the " \
        "#{file_name} factory, and the 'a verifiable model for verification state' + 'Geo Framework " \
        "selective sync behavior' shared examples to its model spec", :yellow)
    end

    # -- Framework-file patching -------------------------------------------
    # Each patch resets onto whatever is already in the file, inserting only this replicable's
    # entry. inject_into_file is idempotent (skips if the entry is already present). A missing
    # anchor in an existing file is a hard error so an incomplete generation can't slip through;
    # a missing target file is skipped (e.g. the generator test sandbox).

    def destination_path(path)
      Gitlab::PathTraversal.check_path_traversal!(path)
      File.join(destination_root, path)
    end

    def target_present?(path)
      return true if File.exist?(destination_path(path))

      say_status(:skip, "#{path} (not found)", :yellow)
      false
    end

    def ensure_anchor!(path, anchor)
      content = File.read(destination_path(path))
      pattern = anchor.is_a?(Regexp) ? anchor : Regexp.new(Regexp.escape(anchor))
      return if content.match?(pattern)

      raise Thor::Error, "Anchor not found in #{path}: #{anchor.inspect}"
    end

    # Insert `line` (no trailing newline) on the line after the one containing `anchor`.
    def insert_line_after(path, anchor, line)
      return unless target_present?(path)

      ensure_anchor!(path, anchor)
      inject_into_file path, "#{line}\n", after: /.*#{Regexp.escape(anchor)}.*\n/
    end

    # Insert `line` at its alphabetical position inside the list region between the line
    # containing `open` and the next line matching `close`. `sort_key` is a regexp with one
    # capture group identifying the comparable token; it is matched against `line` and each
    # region line (non-matching lines, e.g. blanks or delimiters, are ignored). For a
    # comma-delimited list the trailing comma is rebalanced when the new entry sorts last.
    # Idempotent: a no-op when an entry with the same key already exists.
    def insert_sorted(path, line, sort_key:, open:, close:)
      return unless target_present?(path)

      new_key = line[sort_key, 1]
      raise Thor::Error, "Cannot determine sort key in #{path} for: #{line.strip.inspect}" unless new_key

      lines = File.readlines(destination_path(path))

      open_i = lines.index { |l| l.include?(open) }
      raise Thor::Error, "Anchor not found in #{path}: #{open.inspect}" unless open_i

      close_i = ((open_i + 1)...lines.size).find { |i| lines[i].match?(close) }
      raise Thor::Error, "List end not found in #{path}: #{close.inspect}" unless close_i

      entries = ((open_i + 1)...close_i).select { |i| lines[i][sort_key, 1] }
      raise Thor::Error, "No list entries found in #{path}" if entries.empty?
      return if entries.any? { |i| lines[i][sort_key, 1] == new_key }

      successor = entries.find { |i| lines[i][sort_key, 1] > new_key }

      if successor
        lines.insert(successor, "#{line.rstrip}\n")
      elsif line.rstrip.end_with?(',')
        # New entry sorts last in a comma-delimited list: give the previous last a trailing
        # comma and drop it from the new (now last) entry.
        last = entries.last
        lines[last] = "#{lines[last].rstrip.chomp(',')},\n"
        lines.insert(last + 1, "#{line.rstrip.chomp(',')}\n")
      else
        lines.insert(entries.last + 1, "#{line.rstrip}\n")
      end

      create_file path, lines.join, force: true, verbose: false
    end

    def patch_replicator_classes
      insert_sorted('ee/lib/gitlab/geo.rb', "      ::Geo::#{replicator_class_name},",
        sort_key: /::Geo::(\w+)/, open: 'REPLICATOR_CLASSES = [', close: /^\s*\]\.freeze/)
    end

    def patch_geo_node_type
      path = 'ee/app/graphql/types/geo/geo_node_type.rb'
      return unless target_present?(path)

      return if File.read(destination_path(path)).include?("field :#{graphql_field_name}")

      ensure_anchor!(path, 'field :verification_max_capacity')

      field = <<~RUBY
        field :#{graphql_field_name}, ::Types::Geo::#{registry_type_class_name}.connection_type,
          null: true,
          resolver: ::Resolvers::Geo::#{resolver_class_name},
          description: 'Find #{replicable_title} registries on this Geo node. ' \\
                       'Ignored if `#{replication_feature_flag_name}` feature flag is disabled.',
          experiment: { milestone: '#{milestone}' }
      RUBY

      inject_into_file path, indent(field, 6), before: /^\s*field :verification_max_capacity/
    end

    def patch_inflections
      insert_line_after('config/initializers_before_autoloader/000_inflections.rb',
        'packages_helm_metadata_cache_registry', "    #{registry_table_name}")
    end

    def patch_geo_node_type_spec
      insert_sorted('ee/spec/graphql/types/geo/geo_node_type_spec.rb', "      #{graphql_field_name}",
        sort_key: /^\s+(\w+_registries)\s*$/, open: 'expected_fields = %i[', close: /^\s*\]/)
    end

    def patch_registry_class_enum_spec
      insert_sorted('ee/spec/graphql/types/geo/registry_class_enum_spec.rb', "      #{enum_key}",
        sort_key: /^\s+([A-Z][A-Z0-9_]+)\s*$/, open: '%w[', close: /^\s*\]/)
    end

    def patch_registries_shared_context
      path = 'ee/spec/support/shared_contexts/graphql/geo/registries_shared_context.rb'
      # Pad to the widest row currently in the table so the pipes line up with it.
      col1 = "Geo::#{registry_class_name}".ljust(59)
      col2 = "Types::Geo::#{registry_type_class_name}".ljust(70)
      line = "    #{col1}| #{col2}| :geo_#{file_name}_registry"

      insert_sorted(path, line,
        sort_key: /^\s*Geo::(\w+)/, open: 'where(:registry_class', close: /^\s*end\b/)
    end

    # The shared-example blocks are kept sorted by registry_class_name, so insert the new one at its
    # alphabetical position (falling back to before the final `end`) to keep rebases conflict-free.
    def patch_registries_spec
      path = 'ee/spec/requests/api/graphql/geo/registries_spec.rb'
      return unless target_present?(path)

      lines = File.readlines(destination_path(path))
      return if lines.any? { |l| l.include?("geo_#{file_name}_registry") }

      block = indent(<<~RUBY, 2)
        it_behaves_like 'gets registries for', {
          field_name: '#{graphql_registries_field_camel}',
          registry_class_name: '#{registry_class_name}',
          registry_factory: :geo_#{file_name}_registry,
          registry_foreign_key_field_name: '#{graphql_foreign_key_field_camel}'
        }
      RUBY

      successor = lines.index do |l|
        m = l.match(/registry_class_name: '(\w+)'/)
        m && m[1] > registry_class_name
      end

      if successor
        successor -= 1 until lines[successor].include?("it_behaves_like 'gets registries for'")
        lines.insert(successor, "#{block}\n")
      else
        end_idx = lines.rindex { |l| l.match?(/^end\s*$/) }
        lines.insert(end_idx, "\n#{block}")
      end

      create_file path, lines.join, force: true, verbose: false
    end

    # rubocop:disable Layout/LineLength -- Anchor and assertion strings mirror the generated
    # spec lines, which legitimately exceed 120 chars.
    def patch_registry_consistency_worker_spec
      path = 'ee/spec/workers/geo/secondary/registry_consistency_worker_spec.rb'
      return unless target_present?(path)

      content = File.read(destination_path(path))
      return if content.include?("Geo::#{registry_class_name}")

      anchors = worker_spec_anchors
      anchor_create = anchors[:create]
      anchor_pre = anchors[:pre]
      anchor_post = anchors[:post]
      creation = anchors[:creation]

      [anchor_create, anchor_pre, anchor_post].each do |anchor|
        raise Thor::Error, "Anchor not found in #{path}: #{anchor.inspect}" unless content.include?(anchor)
      end

      gsub_file path, anchor_create, "#{anchor_create}\n#{creation}"
      gsub_file path, anchor_pre,
        "#{anchor_pre}\n        expect(Geo::#{registry_class_name}.where(#{foreign_key_name}: #{file_name}.id).count).to eq(0)"
      gsub_file path, anchor_post,
        "#{anchor_post}\n        expect(Geo::#{registry_class_name}.where(#{foreign_key_name}: #{file_name}.id).count).to eq(1)"
    end

    # Existing anchors in the worker spec to insert the new replicable after. Defaults to the
    # regular-blob set; the upload-partition blob overrides it.
    def worker_spec_anchors
      {
        create: 'helm_metadata_cache = create(:helm_metadata_cache)',
        pre: 'expect(Geo::PackagesHelmMetadataCacheRegistry.where(packages_helm_metadata_cache_id: helm_metadata_cache.id).count).to eq(0)',
        post: 'expect(Geo::PackagesHelmMetadataCacheRegistry.where(packages_helm_metadata_cache_id: helm_metadata_cache.id).count).to eq(1)',
        creation: "        #{file_name} = create(:#{file_name})"
      }
    end
    # rubocop:enable Layout/LineLength

    def patch_possible_types_json
      path = 'app/assets/javascripts/graphql_shared/possible_types.json'
      return unless target_present?(path)

      data = Gitlab::Json.safe_parse(File.read(destination_path(path)))
      list = data['Registrable']
      return unless list && list.exclude?(registry_class_name)

      list << registry_class_name
      list.sort!
      create_file path, "#{Gitlab::Json.pretty_generate(data)}\n", force: true
    end

    # -- Geo status fixtures, API docs and prometheus metrics --------------
    # The status field schema, API-doc values and prometheus rows live in
    # Geo::Replicator::StatusSchema.

    delegate :status_field_prefix, :status_property_definitions, :status_fields,
      :api_doc_json_fields, :prometheus_metrics_rows, to: :status_schema, private: true

    def status_schema
      @status_schema ||= ::Geo::Replicator::StatusSchema.new(
        file_name: file_name, replicable_title_plural: replicable_title_plural, milestone: milestone
      )
    end

    def patch_geo_status_json(path)
      return unless target_present?(path)

      data = Gitlab::Json.safe_parse(File.read(destination_path(path)))
      return if data['required']&.include?("#{status_field_prefix}_count")

      index = data['required']&.index(GEO_STATUS_ANCHOR)
      raise Thor::Error, "Anchor not found in #{path}: #{GEO_STATUS_ANCHOR.inspect}" unless index

      data['required'].insert(index, *status_fields)

      properties = {}
      data['properties'].each do |key, value|
        if key == GEO_STATUS_ANCHOR
          status_property_definitions.each do |field, definition|
            properties[field] = definition
          end
        end

        properties[key] = value
      end
      data['properties'] = properties

      create_file path, "#{Gitlab::Json.pretty_generate(data)}\n", force: true
    end

    def patch_geo_api_doc(path)
      return unless target_present?(path)
      return if File.read(destination_path(path)).include?("\"#{status_field_prefix}_count\"")

      ensure_anchor!(path, GEO_STATUS_ANCHOR)

      gsub_file path, /^( *)"#{GEO_STATUS_ANCHOR}"/o do |match|
        "#{api_doc_json_fields(Regexp.last_match(1))}\n#{match}"
      end
    end

    def patch_prometheus_metrics_doc
      path = 'doc/administration/monitoring/prometheus/gitlab_metrics.md'
      return unless target_present?(path)
      return if File.read(destination_path(path)).include?("geo_#{status_field_prefix}")

      ensure_anchor!(path, '| `geo_status_failed_total`')

      inject_into_file path, "#{prometheus_metrics_rows}\n", before: /^\| `geo_status_failed_total`/
    end

    def indent(text, spaces)
      pad = ' ' * spaces
      text.each_line.map { |l| l.strip.empty? ? l : "#{pad}#{l}" }.join
    end

    # -- Subclass hooks -----------------------------------------------------
    # Defaults describe a replicable that wraps an existing model (regular blob, repository); the
    # upload-partition blob overrides them.

    # Generate files specific to this replicable type (e.g. the partition index migration). No-op.
    def create_type_specific_files; end

    # Extra generated Ruby files for the RuboCop autocorrect pass.
    def type_specific_ruby_files
      [model_ee_concern_path]
    end

    # Whether --model-class must be provided. Subclasses that derive it may relax this.
    def model_class_required?
      true
    end

    # Whether --sharding-key may be omitted. Subclasses supporting a no-sharding-key mode
    # (cell-setting/instance-wide replicables with no organization, namespace, or project)
    # relax this.
    def sharding_key_optional?
      false
    end

    # Extra validation errors a subclass needs (e.g. mode-specific flag combinations). The
    # returned strings are appended to the errors raised by validate!. None by default.
    def extra_validation_errors
      []
    end

    def sharding_key_missing?
      sharding_keys.empty? && !sharding_key_optional?
    end

    # Per-type template for the replicator model; subclasses override it for their strategy.
    def replicator_model_template
      'models/replicator.rb.tt'
    end

    # Per-type template for the replicator spec.
    def replicator_spec_template
      'specs/replicator_spec.rb.tt'
    end

    # Extra framework-file patches a subclass needs (e.g. repository types). No-op by default.
    def extra_framework_patches; end

    # Template fragments; empty for the default flavor, filled by the upload-partition blob.
    def replicator_strategy_includes
      ''
    end

    def registry_partition_includes
      ''
    end

    def registry_partition_class_methods
      ''
    end

    # Extra registry migration columns; only blob registries record where the file lives.
    def registry_extra_columns
      ''
    end

    def registry_shared_examples
      "include_examples 'a Geo framework registry'"
    end

    # -- Options ------------------------------------------------------------

    def table_name
      options[:table_name]
    end

    def milestone
      options[:milestone]
    end

    def model_class
      options[:model_class].presence
    end

    def sharding_keys
      @sharding_keys ||= Array(options[:sharding_key]).flat_map { |k| k.split(',') }.map(&:strip).reject(&:empty?).uniq
    end

    def sharding_key
      sharding_keys.first
    end

    # -- Names --------------------------------------------------------------
    # file_name and class_name come from NamedBase (snake_case and CamelCase of NAME); the rest of
    # the naming derivations live in Geo::Replicator::Naming.

    delegate :replicable_title, :replicable_title_plural, :registry_table_name, :state_table_name,
      :foreign_key_name, :registry_class_name, :replicator_class_name, :state_class_name,
      :finder_class_name, :resolver_class_name, :registry_type_class_name, :enum_key,
      :registry_factory_replicable_name, :graphql_field_name, :graphql_field_name_camel,
      :graphql_registries_field_camel, :graphql_foreign_key_field_camel,
      :replication_feature_flag_name, :force_primary_checksumming_feature_name,
      :model_factory_name, :parent_model_factory_name, to: :naming, private: true

    def naming
      @naming ||= ::Geo::Replicator::Naming.new(
        file_name: file_name, class_name: class_name, model_class: model_class,
        upload_partition: false, parent_factory: nil
      )
    end

    def migration_version
      MIGRATION_VERSION
    end

    def feature_issue_url
      FEATURE_ISSUE_URL
    end

    # -- Model references ---------------------------------------------------

    def replicator_model_reference
      "::#{model_class}"
    end

    def carrierwave_uploader_body
      'model_record.file'
    end

    def registry_belongs_to_class
      model_class
    end

    def registry_model_class_reference
      "::#{model_class}"
    end

    def state_belongs_to_class
      model_class
    end

    # -- Selective sync -----------------------------------------------------
    # The selective-sync scope body, sharding-key scope and model-spec fixtures live in
    # Geo::Replicator::SelectiveSync.

    delegate :scope_definition, :selective_sync_scope_body, :selective_sync_fixtures,
      :raw_selective_sync_scope_body, to: :selective_sync, private: true

    def selective_sync
      @selective_sync ||= ::Geo::Replicator::SelectiveSync.new(
        sharding_key: sharding_key, file_name: file_name,
        parent_model_factory_name: parent_model_factory_name
      )
    end

    # -- Sharding-key migration helpers ------------------------------------

    attr_reader :current_sharding_key

    def current_sharding_key_camel
      current_sharding_key.split('_').map(&:capitalize).join
    end

    def sharding_key_reference_table_for(key)
      {
        'project_id' => 'projects',
        'namespace_id' => 'namespaces',
        'organization_id' => 'organizations',
        'uploaded_by_user_id' => 'users'
      }[key]
    end

    def sharding_key_column_definition
      if sharding_keys.size == 1
        "t.bigint :#{sharding_key}, null: false"
      else
        sharding_keys.map { |k| "t.bigint :#{k}" }.join("\n              ")
      end
    end

    def sharding_key_index_definition
      if sharding_keys.size == 1
        "t.index :#{sharding_key}"
      else
        sharding_keys.map { |k| "t.index :#{k}" }.join("\n              ")
      end
    end

    def state_fk_lines
      lines = []

      sharding_keys.each do |key|
        ref = sharding_key_reference_table_for(key)
        lines << "add_concurrent_foreign_key :#{state_table_name}, :#{ref}, column: :#{key}, on_delete: :cascade"
      end

      if sharding_keys.size > 1
        cols = sharding_keys.map { |k| ":#{k}" }.join(', ')
        lines << "add_multi_column_not_null_constraint(:#{state_table_name}, #{cols})"
      end

      lines
    end

    # The FK to the parent table is inline in create_table for the default (existing-model) flow.
    # Subclasses referencing a composite-PK table (upload partition) override this.
    def state_inline_foreign_key
      ",\n                foreign_key: { on_delete: :cascade }"
    end

    def sharding_key_yaml_entries
      sharding_keys.map { |key| "  #{key}: #{sharding_key_reference_table_for(key)}" }.join("\n")
    end

    # gitlab_schema for the generated *_states table dictionary. Defaults to the org schema;
    # the no-sharding-key (cell-setting) mode overrides it.
    def state_gitlab_schema
      'gitlab_main_org'
    end

    # Name of the node argument in the generated selective_sync_scope override. Sharded
    # replicables consult the node; always-replicated (no-sharding-key) ones don't, so the
    # argument is prefixed to avoid an unused-argument warning.
    def selective_sync_node_arg
      sharding_keys.any? ? 'node' : '_node'
    end

    # -- Timestamps ---------------------------------------------------------

    def base_time
      @base_time ||= Time.now.utc
    end

    def geo_migration_timestamp
      base_time.strftime('%Y%m%d%H%M%S')
    end

    def state_timestamp
      (base_time + 1).strftime('%Y%m%d%H%M%S')
    end

    def trigger_timestamp(index)
      (base_time + 2 + index).strftime('%Y%m%d%H%M%S')
    end
  end
end
