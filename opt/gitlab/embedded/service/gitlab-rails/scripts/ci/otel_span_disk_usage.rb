# frozen_string_literal: true

require 'open3'
require 'timeout'

# Filesystem availability is shared and may exclude job-specific quota constraints.
class OtelSpanDiskUsage
  PREFIX = 'gitlab.cicd.disk.'
  MEASUREMENTS = %w[space_total_bytes space_available_bytes inodes_available].freeze
  MAX_INT64 = (1 << 63) - 1
  # Shorter than the exporter's enrichment budget, so a slow `stat` drops only disk data while cgroup data survives.
  STAT_TIMEOUT_S = 0.5

  # Raised only by this class's own deadline, so an enclosing enrichment timeout is never mistaken for it.
  StatTimeout = Class.new(StandardError)

  def initialize(project_dir: ENV['CI_PROJECT_DIR'])
    @project_dir = project_dir
  end

  # @return [Hash{String => Array, Integer}] project-filesystem snapshot, or {} when unavailable
  def snapshot
    return {} unless @project_dir && File.directory?(@project_dir)
    return {} unless RUBY_PLATFORM.include?('linux')

    stat = File.stat(@project_dir)
    output, status = filesystem_stat
    return {} unless status.success?

    parse_snapshot(output, stat.dev)
  rescue SystemCallError, IOError, StatTimeout
    {}
  end

  # @param previous [Hash, nil] start filesystem snapshot
  # @param current [Hash, nil] end filesystem snapshot
  # @return [Hash{String => Integer, String}] boundary observations, or {} for mismatched snapshots
  def attributes(previous, current)
    return {} unless previous.is_a?(Hash) && current.is_a?(Hash)
    return {} unless current['identity'] && previous['identity'] == current['identity']

    values = {}
    { 'start' => previous, 'end' => current }.each do |boundary, snapshot|
      MEASUREMENTS.each do |key|
        value = snapshot[key]
        next unless value.is_a?(Integer) && value.between?(0, MAX_INT64)

        suffix = key.end_with?('_bytes') ? key.sub('_bytes', "_#{boundary}_bytes") : "#{key}_#{boundary}"
        values["#{PREFIX}#{suffix}"] = value
      end
    end
    values["#{PREFIX}scope"] = 'project_filesystem' unless values.empty?
    values
  end

  private

  def parse_snapshot(output, device)
    fields = output.strip.split
    return {} unless fields.size == 5 && fields.last.match?(/\A[0-9a-f]+\z/)
    return {} unless fields.first(4).all? { |field| field.match?(/\A[0-9]+\z/) }

    block_size, blocks, available, inodes = fields.first(4).map(&:to_i)
    return {} unless block_size > 0 && available <= blocks

    {
      'identity' => [device, fields.last],
      'space_total_bytes' => block_size * blocks,
      'space_available_bytes' => block_size * available,
      'inodes_available' => inodes
    }
  end

  def filesystem_stat
    # Both BusyBox and GNU stat support this format; no shell expansion or human-readable df parsing.
    command = ['stat', '-f', '-c', '%S %b %a %d %i', '--', @project_dir]
    # Defer outer timeouts until the child has a cleanup handler, including during Open3's setup.
    Thread.handle_interrupt(Exception => :never) do
      Open3.popen3({ 'LC_ALL' => 'C' }, *command) do |stdin, stdout, stderr, waiter|
        Thread.handle_interrupt(Exception => :immediate) do
          stdin.close
          Timeout.timeout(STAT_TIMEOUT_S, StatTimeout) do
            # IO#read(length) returns nil at EOF, so a successful stat with no output is possible.
            output = stdout.read(1024).to_s
            stderr.read(1024)
            [output, waiter.value]
          end
        end
      ensure
        Process.kill('KILL', waiter.pid) if waiter.alive?
      end
    end
  end
end
