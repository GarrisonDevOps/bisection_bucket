# frozen_string_literal: true

return if Rails.env.production?

namespace :gitlab do
  namespace :nav do
    desc "GitLab | Nav | Dump the complete navigation structure for all navigation contexts"
    task :dump_structure, [:user_id] => :gitlab_environment do |_t, args|
      user = args[:user_id] ? User.find(args[:user_id]) : User.first
      dumper = Tasks::Gitlab::Nav::DumpStructure.new(user: user)
      variants = Tasks::Gitlab::Nav::VariantGenerator.new(dumper: dumper)
      contexts = variants.dump

      puts YAML.dump({
        generated_at: dumper.current_time,
        commit_sha: dumper.current_sha,
        contexts: contexts
      }.deep_stringify_keys)
    end
  end
end
