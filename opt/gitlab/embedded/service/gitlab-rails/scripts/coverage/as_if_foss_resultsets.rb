# frozen_string_literal: true

# The as-if-foss RSpec jobs run in the gitlab-foss project, so their SimpleCov
# resultsets record paths under that project's directory. Unless the paths are
# rewritten to this project's, SimpleCov drops them as files that don't exist
# here, and their coverage of CE code that EE overrides is lost.
class AsIfFossResultsets
  def initialize(root:, foss_root: File.join(File.dirname(root), 'gitlab-foss'))
    @from = %("#{foss_root}/)
    @to = %("#{root}/)
  end

  def rewrite(files)
    rewritten = 0

    files.each do |file|
      content = File.read(file)
      next unless content.include?(@from)

      File.write(file, content.gsub(@from, @to))
      rewritten += 1
    end

    rewritten
  end
end
