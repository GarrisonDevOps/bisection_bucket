# frozen_string_literal: true

# Adapters for the ports the `gitlab-diff` gem declares on
# `Gitlab::Diff::Configuration`.
Gitlab::Diff.configure do |config|
  config.diff_line_code = ->(file_path, new_pos, old_pos) { Gitlab::Git.diff_line_code(file_path, new_pos, old_pos) }
  config.binary_notice = ->(text) { Gitlab::Git::Diff.has_binary_notice?(text) }
  config.serialize_line = ->(line) { DiffLineSerializer.new.represent(line) }
end
