# frozen_string_literal: true

# SPIKE (gitlab-org/gitlab#602803): thin CLI over Gitlab::Geo::Tools. `cleanup_check` is
# read-only; `resolve` is dry-run unless DRY_RUN=false. The logic lives in Gitlab::Geo::Tools
# so it can also be run from a Rails console without invoking rake.
namespace :geo do
  namespace :tools do
    # Validated here rather than in the resolution so a bad value can never reach a query, and
    # so the console path stays explicit (Resolutions.for(..., min_retry_count: 10)) instead of
    # reading ENV from the model layer.
    parse_env_integer = ->(name, allow_zero: false) do
      raw = ENV[name].presence
      next nil unless raw

      value = Integer(raw, exception: false)
      valid = value && (allow_zero ? value >= 0 : value > 0)
      expected = allow_zero ? 'a non-negative integer' : 'a positive integer'

      abort "#{name} must be #{expected}, got: #{raw.inspect}" unless valid

      value
    end

    desc 'GitLab | Geo | Tools | Scan for known Geo replication errors and recommend fixes ' \
      '(pass a key to check one error only; FORMAT=json for machine-readable output)'
    task :cleanup_check, [:key] => :gitlab_environment do |_task, args|
      key = args[:key]
      # 0 means "no retry-count gate", which matches the manual procedure in the docs: it
      # leaves the per-record storage check as the only guard before a record is a candidate.
      min_retry_count = parse_env_integer.call('MIN_RETRY_COUNT', allow_zero: true)
      output_format = ENV['FORMAT'].presence&.strip || 'text'

      known_error = nil

      if key.present?
        known_error = Geo::Tools::KnownErrors.find(key, min_retry_count: min_retry_count)

        abort "Unknown error key: #{key}" unless known_error
      end

      begin
        Gitlab::Geo::Tools.cleanup_check(known_error, output_format: output_format,
          min_retry_count: min_retry_count)
      rescue Gitlab::Geo::Tools::UnsupportedFormatError => ufe
        abort ufe.message
      end
    end

    desc 'GitLab | Geo | Tools | Resolve a known Geo error by key (DRY_RUN=true by default)'
    task :resolve, [:key] => :gitlab_environment do |_task, args|
      key = args[:key]
      min_retry_count = parse_env_integer.call('MIN_RETRY_COUNT', allow_zero: true)
      # Only resolve writes a recovery dump, so only resolve takes the override. Where it lands is
      # checked before anything is destroyed, not here, so a console caller gets the same guard.
      known_error = Geo::Tools::KnownErrors.find(
        key,
        min_retry_count: min_retry_count,
        recovery_dump_dir: ENV['RECOVERY_DUMP_DIR'].presence
      )

      abort "Unknown error key: #{key}" unless known_error

      limit = parse_env_integer.call('LIMIT')

      Gitlab::Geo::Tools.resolve(
        known_error,
        dry_run: ENV['DRY_RUN'] != 'false',
        limit: limit
      )
    end
  end
end
