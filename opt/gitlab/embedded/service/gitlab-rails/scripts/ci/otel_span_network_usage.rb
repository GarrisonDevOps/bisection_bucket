# frozen_string_literal: true

require 'socket'

class OtelSpanNetworkUsage
  PREFIX = 'gitlab.cicd.network.'
  MAX_BYTES = 32_768
  # OTLP int values are signed 64-bit; a larger value would invalidate the whole span payload.
  MAX_INT64 = (1 << 63) - 1

  def initialize(counters_file: '/proc/net/dev', namespace_file: '/proc/self/ns/net')
    @counters_file = counters_file
    @namespace_file = namespace_file
  end

  # @return [Hash{String => Array, Integer, String}] single-interface snapshot, or {} when unavailable or ambiguous
  def snapshot
    return {} unless RUBY_PLATFORM.include?('linux')

    namespace = namespace_identity
    interfaces = inventory
    # Inactive interfaces, such as tunnels added by kernel modules, carry no traffic and would make selection ambiguous.
    eligible = interfaces.select { |_, _, loopback, up| up && !loopback }
    return {} unless eligible.size == 1

    name = eligible.first.first
    counters = read_counters
    return {} unless counters.keys.sort == interfaces.map(&:first).sort
    return {} unless interfaces == inventory

    {
      'identity' => [namespace, interfaces],
      'interface_name' => name,
      'receive_bytes' => counters.fetch(name).first,
      'transmit_bytes' => counters.fetch(name).last
    }
  rescue SystemCallError, IOError, ArgumentError
    {}
  end

  # @param previous [Hash, nil] start network snapshot
  # @param current [Hash, nil] end network snapshot
  # @return [Hash{String => Integer, String}] byte deltas and scope, or {} for invalid counters or identity changes
  def attributes(previous, current)
    return {} unless previous.is_a?(Hash) && current.is_a?(Hash)
    return {} unless current['identity'] && previous['identity'] == current['identity']

    values = %w[receive_bytes transmit_bytes].filter_map do |key|
      start = previous[key]
      finish = current[key]
      next unless counter?(start) && counter?(finish) && finish >= start

      ["#{PREFIX}#{key}", finish - start]
    end.to_h
    return {} unless values.size == 2

    values.merge("#{PREFIX}scope" => 'current_network_namespace',
      "#{PREFIX}interface.name" => current['interface_name'])
  end

  private

  def counter?(value)
    value.is_a?(Integer) && value.between?(0, MAX_INT64)
  end

  def namespace_identity
    stat = File.stat(@namespace_file)
    [stat.dev, stat.ino]
  end

  def inventory
    Socket.getifaddrs.map do |interface|
      flags = interface.flags
      [interface.name, interface.ifindex, (flags & Socket::IFF_LOOPBACK) != 0, (flags & Socket::IFF_UP) != 0]
    end.uniq.sort
  end

  def read_counters
    # IO#read(length) returns nil at EOF, which is what an empty file produces.
    text = File.open(@counters_file) { |file| file.read(MAX_BYTES + 1).to_s }
    raise ArgumentError if text.bytesize > MAX_BYTES

    text.lines.drop(2).to_h do |line|
      name, fields = line.strip.split(':', 2)
      values = fields.to_s.split
      raise ArgumentError unless values.size == 16 && values.all? { |value| value.match?(/\A[0-9]+\z/) }

      [name, [Integer(values[0], 10), Integer(values[8], 10)]]
    end
  end
end
