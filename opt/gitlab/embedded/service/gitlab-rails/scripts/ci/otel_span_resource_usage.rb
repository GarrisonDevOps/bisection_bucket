# frozen_string_literal: true

require 'json'
require_relative 'otel_span_disk_usage'
require_relative 'otel_span_network_usage'

# Measures the current cgroup, not exclusive command usage. Other processes in the same subtree contribute.
class OtelSpanResourceUsage
  PREFIX = 'gitlab.cicd.resource_usage.'
  MAX_BYTES = 32_768
  # OTLP int values are signed 64-bit; anything larger would invalidate the whole span payload.
  MAX_INT64 = OtelSpanDiskUsage::MAX_INT64
  MAX_ANCESTORS = 64
  EVENTS = %w[high max oom oom_kill].freeze

  def initialize(
    cgroup_file: '/proc/self/cgroup', mountinfo_file: '/proc/self/mountinfo', disk: OtelSpanDiskUsage.new,
    network: OtelSpanNetworkUsage.new, network_enabled: false)
    @cgroup_file = cgroup_file
    @mountinfo_file = mountinfo_file
    @disk = disk
    @network = network
    @network_enabled = network_enabled
  end

  # @return [Hash{String => Object}] current-cgroup and project-filesystem snapshot, or {} if oversized
  def snapshot
    result = cgroup_snapshot
    disk = @disk.snapshot
    result['disk'] = disk unless disk.empty?
    if @network_enabled
      network = @network.snapshot
      result['network'] = network unless network.empty?
    end

    JSON.generate(result).bytesize <= MAX_BYTES ? result : {}
  end

  # @param previous_json [String] start snapshot JSON
  # @return [Hash{String => Integer, Float, String}] deltas and boundary observations, or {} when invalid
  def attributes(previous_json)
    return {} if previous_json.to_s.bytesize > MAX_BYTES

    previous = JSON.parse(previous_json.to_s)
    current = snapshot
    return {} unless previous.is_a?(Hash)

    independent_attributes = @disk.attributes(previous['disk'], current['disk'])
    if @network_enabled
      network_attributes = @network.attributes(previous['network'], current['network'])
      independent_attributes = independent_attributes.merge(network_attributes)
    end

    return independent_attributes unless current['identity'] && previous['identity'] == current['identity']

    values = {}
    cpu = delta(previous['cpu_usage_usec'], current['cpu_usage_usec'])
    values['cpu_time_seconds'] = cpu / 1_000_000.0 if cpu
    add_memory(values, previous, 'start')
    add_memory(values, current, 'end')
    EVENTS.each do |event|
      value = delta(hash_value(previous, 'events')[event], hash_value(current, 'events')[event])
      values["memory_events_#{event}"] = value if value
    end
    return independent_attributes if values.empty?

    values.merge('scope' => 'current_cgroup', 'source' => 'cgroup_v2')
      .transform_keys { |key| "#{PREFIX}#{key}" }
      .merge(independent_attributes)
  rescue JSON::ParserError, SystemCallError, IOError, ArgumentError
    {}
  end

  private

  def cgroup_snapshot
    directory, mountpoint = locate_cgroup
    return {} unless directory

    stat = File.stat(directory)
    result = {
      'identity' => [directory, stat.dev, stat.ino],
      'cpu_usage_usec' => counters(directory, 'cpu.stat')['usage_usec'],
      'memory_bytes' => number(directory, 'memory.current'),
      'memory_limit_bytes' => number(directory, 'memory.max'),
      'events' => counters(directory, 'memory.events'),
      'ancestors' => ancestor_memory(directory, mountpoint)
    }
    JSON.generate(result).bytesize <= MAX_BYTES ? result : {}
  rescue SystemCallError, IOError, ArgumentError
    {}
  end

  # The previous snapshot crosses a process boundary as JSON, so its nested values can have unexpected types.
  def hash_value(snapshot, key)
    value = snapshot[key]
    value.is_a?(Hash) ? value : {}
  end

  def ancestor_snapshots(snapshot)
    value = snapshot['ancestors']
    value.is_a?(Array) ? value.grep(Hash) : []
  end

  def locate_cgroup
    membership = read(@cgroup_file).lines.find { |line| line.start_with?('0::') }&.strip&.delete_prefix('0::')
    return unless membership&.start_with?('/')
    return if membership.split('/').include?('..')

    cgroup_mounts.each do |root, mountpoint|
      relative = relative_membership(membership, root)
      next unless relative

      directory = File.expand_path(relative, mountpoint)
      next if membership == '/' && root != '/' && !contains_process?(directory)

      return [directory, mountpoint] if File.directory?(directory)
    end

    nil
  end

  def relative_membership(membership, root)
    return '' if membership == '/'
    return unless root == '/' || membership == root || membership.start_with?("#{root}/")

    membership.delete_prefix(root).delete_prefix('/')
  end

  def contains_process?(directory)
    read(File.join(directory, 'cgroup.procs')).lines.any? { |line| line.strip == Process.pid.to_s }
  rescue SystemCallError, IOError
    false
  end

  def cgroup_mounts
    read(@mountinfo_file).lines.filter_map do |line|
      mount, filesystem = line.split(' - ', 2)
      next unless filesystem&.split&.first == 'cgroup2'

      fields = mount.split
      root, mountpoint = fields.values_at(3, 4).map { |value| unescape(value) }
      next unless root && mountpoint

      [root, mountpoint]
    end
  end

  def unescape(value)
    value&.gsub(/\\([0-7]{3})/) { Regexp.last_match(1).to_i(8).chr }
  end

  def read(path)
    # IO#read(length) returns nil at EOF, which is what an empty cgroup file produces.
    File.open(path) { |file| file.read(MAX_BYTES).to_s }
  end

  def number(directory, filename)
    text = read(File.join(directory, filename)).strip
    Integer(text, 10) if text.match?(/\A[0-9]+\z/)
  rescue SystemCallError, IOError, ArgumentError
    nil
  end

  def counters(directory, filename)
    read(File.join(directory, filename)).lines.filter_map do |line|
      key, text = line.split
      [key, Integer(text, 10)] if text&.match?(/\A[0-9]+\z/)
    end.to_h
  rescue SystemCallError, IOError, ArgumentError
    {}
  end

  def ancestor_memory(directory, mountpoint)
    ancestors = []
    MAX_ANCESTORS.times do
      break if directory == mountpoint

      directory = File.dirname(directory)
      stat = File.stat(directory)
      ancestors << {
        'identity' => [directory, stat.dev, stat.ino],
        'memory_bytes' => number(directory, 'memory.current'),
        'memory_limit_bytes' => number(directory, 'memory.max')
      }
    end
    ancestors
  rescue SystemCallError, IOError
    ancestors
  end

  def valid_measurement?(value)
    value.is_a?(Integer) && value.between?(0, MAX_INT64)
  end

  def delta(previous, current)
    return unless valid_measurement?(previous) && valid_measurement?(current) && current >= previous

    current - previous
  end

  def headroom(snapshot)
    usage = snapshot['memory_bytes']
    limit = snapshot['memory_limit_bytes']
    return unless valid_measurement?(usage) && valid_measurement?(limit)

    [limit - usage, 0].max
  end

  def add_memory(values, snapshot, boundary)
    %w[memory_bytes memory_limit_bytes].each do |key|
      value = snapshot[key]
      values[key.sub('_bytes', "_#{boundary}_bytes")] = value if valid_measurement?(value)
    end
    own_headroom = headroom(snapshot)
    values["memory_headroom_#{boundary}_bytes"] = own_headroom if own_headroom
    ancestor_headrooms = ancestor_snapshots(snapshot).filter_map { |ancestor| headroom(ancestor) }
    return if ancestor_headrooms.empty?

    # Each ancestor's own usage includes competing descendants. Hidden ancestors are not observable here.
    values["memory_visible_ancestor_headroom_#{boundary}_bytes"] = ancestor_headrooms.min
  end
end
