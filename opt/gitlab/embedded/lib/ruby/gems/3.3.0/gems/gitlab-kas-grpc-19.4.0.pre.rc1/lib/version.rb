SOURCE_DIR = File.absolute_path(File.join(__dir__, '..', '..', '..'))

module Gitlab
  module Agent
    VERSION = File.read(File.join(SOURCE_DIR, 'VERSION')).strip
  end
end

unless Gitlab::Agent::VERSION.match?(/\d+\.\d+\.\d+(-rc\d+)?/)
  abort "Version string #{version.inspect} does not look like a GitLab Agent Release tag (e.g. \"v1.0.2\"). Aborting."
end
