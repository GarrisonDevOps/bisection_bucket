# frozen_string_literal: true

namespace :gitlab do
  namespace :secret_detection do
    namespace :validity_checks do
      desc 'Generate vendor token verifiers + specs from reviewed vendor definition YAMLs ' \
        '(AI-assisted rule development output). Accepts one YAML file or a directory of them; ' \
        'a vendor with several token types gets one YAML per type. ' \
        'Usage: rake "gitlab:secret_detection:validity_checks:generate[path/to/vendor.yml]"'
      task :generate, [:spec_path] => :environment do |_t, args|
        require 'open3'

        path = args[:spec_path]
        raise 'Provide a vendor definition YAML file or a directory of them' if path.blank?

        paths = File.directory?(path) ? Dir.glob(File.join(path, '*.{yml,yaml}')) : [path]
        raise "No vendor definition YAMLs found in #{path}" if paths.empty?

        # build_all validates every definition before anything is generated or
        # written, so one bad YAML fails the whole set up front.
        attrs_list = paths.map { |spec_path| YAML.safe_load_file(spec_path) }
        vendor_definitions = ::Security::SecretDetection::PartnerTokens::Generator::VendorDefinition.build_all(attrs_list)

        generators = vendor_definitions.map do |vendor_definition|
          ::Security::SecretDetection::PartnerTokens::Generator::ClientGenerator.new(vendor_definition)
        end

        all_paths = generators.flat_map { |generator| [generator.client_path, generator.spec_path] }

        # build_all rejects duplicate class_names, but distinct names can still
        # underscore to one path (AbClient/ABClient); the later write would
        # silently clobber the earlier vendor's artifacts.
        duplicate_paths = all_paths.tally.select { |_path, count| count > 1 }.keys
        if duplicate_paths.any?
          raise "Multiple vendor definitions in this batch generate the same file(s): #{duplicate_paths.join(', ')}"
        end

        # Regenerating after editing a YAML is legitimate, but only as an
        # explicit choice: a class-name collision with an existing vendor
        # would otherwise silently clobber its verifier.
        existing = all_paths.select { |file| File.exist?(file) }
        if existing.any? && !Gitlab::Utils.to_boolean(ENV['FORCE'], default: false)
          raise "Refusing to overwrite existing files:\n  #{existing.join("\n  ")}\n" \
            'Re-run with FORCE=true to regenerate them.'
        end

        generators.each do |generator|
          File.write(generator.client_path, generator.client_source)
          File.write(generator.spec_path, generator.spec_source)
        end

        # Normalise indentation/style so the generated files land review-ready.
        # Captured (not silenced) so a failed run surfaces its diagnostics.
        rubocop_output, rubocop_status = Open3.capture2e(
          'bundle', 'exec', 'rubocop', '-a', '--no-server', *all_paths
        )

        unless rubocop_status.success?
          warn "WARNING: rubocop autocorrect did not run cleanly; check the generated files.\n\n" \
            "#{rubocop_output.lines.last(20).join}"
        end

        vendor_definitions.zip(generators).each do |vendor_definition, generator|
          puts "Generated: #{generator.client_path}, #{generator.spec_path}"
          puts 'Add this entry to PartnerTokens::Registry::PARTNERS (ADR 006):'
          puts generator.registry_entry
          puts 'Remaining manual steps:'
          puts '  1. Commit the definition YAML under ' \
            'ee/lib/security/secret_detection/partner_tokens/generator/definitions/ ' \
            '(generated_client_sync_spec.rb fails if it and the generated files get out of sync).'
          puts '  2. Mirror the entry in the registry_spec.rb tables.'
          puts "  3. Ensure a `#{vendor_definition.rate_limit_key}` rule exists in " \
            'ee/lib/ee/gitlab/application_rate_limiter/labkit_adapter/supported_rate_limits.rb.'
          puts '  4. List the token type (and endpoint, if new) in ' \
            'doc/user/application_security/vulnerabilities/validity_check.md.'
          puts '  5. Run the specs and open for review.'
          puts ''
        end
      end

      desc 'Print the generated verifier for a vendor definition YAML without writing files'
      task :preview, [:spec_path] => :environment do |_t, args|
        attrs = YAML.safe_load_file(args[:spec_path])
        vendor_definition = ::Security::SecretDetection::PartnerTokens::Generator::VendorDefinition.new(attrs)
        generator = ::Security::SecretDetection::PartnerTokens::Generator::ClientGenerator.new(vendor_definition)

        puts generator.client_source
      end
    end
  end
end
